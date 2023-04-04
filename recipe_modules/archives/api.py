# Copyright 2022 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import attr
import re

from recipe_engine import recipe_api


@attr.s
class ArchivePaths(object):
  """Paths for an archive config."""
  local = attr.ib(type=str)
  remote = attr.ib(type=str)


ANDROID_ARTIFACTS_BUCKET = 'download.flutter.io'

# Monorepo constant.
MONOREPO = 'monorepo'

# Used for mock paths
DIRECTORY = 'DIRECTORY'

# Relative paths used to mock paths for testing.
MOCK_JAR_PATH = (
    'io/flutter/x86_debug/'
    '1.0.0-0005149dca9b248663adcde4bdd7c6c915a76584/'
    'x86_debug-1.0.0-0005149dca9b248663adcde4bdd7c6c915a76584.jar'
)
MOCK_POM_PATH = (
    'io/flutter/x86_debug/'
    '1.0.0-0005149dca9b248663adcde4bdd7c6c915a76584/'
    'x86_debug-1.0.0-0005149dca9b248663adcde4bdd7c6c915a76584.pom'
)


# Bucket + initial prefix for artifact destination.
LUCI_TO_GCS_PREFIX = {
    'flutter': 'flutter_infra_release',
    MONOREPO: 'flutter_archives_v2/monorepo/flutter_infra_release',
    'prod': 'flutter_infra_release',
    'staging': 'flutter_archives_v2/flutter_infra_release',
    'try': 'flutter_archives_v2/flutter_infra_release',
    'try.shadow': 'flutter_archives_v2/flutter_infra_release'
}

# Bucket + initial prefix for artifact destination.
LUCI_TO_ANDROID_GCS_PREFIX = {
    'flutter': '',
    MONOREPO: 'flutter_archives_v2/monorepo',
    'prod': '',
    'staging': 'flutter_archives_v2',
    'try': 'flutter_archives_v2',
    'try.shadow': 'flutter_archives_v2'
}

# Subpath for realms. A realm is used to separate file destinations
# within the same configuration. E.g. production environment with
# an experimental realm and production environment with a production realm.
REALM_TO_PATH = {
    'production': '',
    'experimental': 'experimental'
}


class ArchivesApi(recipe_api.RecipeApi):
  """Api to handle archives from engine_v2 recipes."""

  def _full_path_list(self, checkout, archive_config):
    """Calculates the local paths using an archive_config.

    Args:
      checkout: (Path) the checkout path of the engine repository.
      archive_config: (dict) a dictionary with the archive files generated by
        a given build.

    Returns:
      A list of strings with the expected local files as described
      by the archive configuration.
    """
    results = []
    self.m.path.mock_add_paths(
        self.m.path['start_dir'].join(
            'out/android_profile/zip_archives/download.flutter.io'),
        DIRECTORY
    )
    for include_path in archive_config.get('include_paths', []):
      full_include_path = self.m.path.abspath(checkout.join(include_path))
      if self.m.path.isdir(full_include_path):
        test_data = [

        ]
        paths = self.m.file.listdir(
                'Expand directory', checkout.join(include_path),
                recursive=True, test_data=(MOCK_JAR_PATH, MOCK_POM_PATH))
        paths = [self.m.path.abspath(p) for p in paths]
        results.extend(paths)
      else:
        results.append(full_include_path)
    return results

  def _split_dst_parts(self, dst):
    """Splits gsutil uri into a bucket and path sections.

    Args:
      dst: (str) a gcs path like gs://bucket/a/b/c.

    Returns:
      A tuple with the bucket as the first item and the path to the
      object as the second parameter.
    """

    matches = re.match('gs://([\w.]+)/(.+)', dst)
    return (matches.group(1), matches.group(2))

  def upload_artifact(self, src, dst, metadata=None):
    """Uploads a local object to a gcs destination.

    This method also ensures the directoy structure is recreated in the
    destination.

    Args:
      src: (str) a string with the object local path.
      dst: (str) a string with the destination path in gcs.
      metadata: (dict) a dictionary with the header as key and its content as value.
    """
    bucket, path = self._split_dst_parts(dst)
    dir_part = self.m.path.dirname(path)
    archive_dir = self.m.path.mkdtemp()
    local_dst_tree = archive_dir.join(*dir_part.split('/'))
    self.m.file.ensure_directory('Ensure %s' % dir_part, local_dst_tree)
    self.m.file.copy('Copy %s to tmp location' % src, src, local_dst_tree)
    self.m.gsutil.upload(
        name='Upload %s to %s' % (src, dst),
        source='%s/*' % archive_dir,
        bucket=bucket,
        dest='',
        args=['-r'],
        metadata=metadata,
    )

  def download(self, src, dst):
    """Downloads a file from GCS.

    Args:
      src: A string with gcs uri to download.
      dst: A string with the local destination for the file.
    """
    bucket, path = self._split_dst_parts(src)
    self.m.gsutil.download(
        bucket, path, dst, name="download %s" % src
    )

  def engine_v2_gcs_paths(self, checkout, archive_config):
    """Calculates engine v2 GCS paths from an archive config.

    Args:
      checkout: (Path) the engine repository checkout folder.
      archive_config: (dict) the archive configuration for a recipes v2 build.

    Returns:
      A list of ArchivePaths with expected local and remote locations for the
      generated artifacts.
    """
    results = []
    # Artifacts bucket is calculated using the LUCI bucket but we also use the realm to upload
    # artifacts to the same bucket but different path when the build configurations use an experimental
    # realm. Defaults to experimental.
    artifact_realm = REALM_TO_PATH.get(archive_config.get('realm', ''), 'experimental')
    # Do not archive if this is a monorepo try build.
    if self.m.monorepo.is_monorepo_try_build:
      return results

    # Calculate prefix and commit.
    is_monorepo = self.m.buildbucket.gitiles_commit.project == MONOREPO
    bucket = MONOREPO if is_monorepo else self.m.buildbucket.build.builder.bucket
    file_list = self._full_path_list(checkout, archive_config)
    if is_monorepo:
      commit = self.m.repo_util.get_commit(checkout.join('../../monorepo'))
    else:
      commit = self.m.repo_util.get_commit(checkout.join('flutter'))

    for include_path in file_list:
      is_android_artifact = ANDROID_ARTIFACTS_BUCKET in include_path
      dir_part = self.m.path.dirname(include_path)
      full_base_path = self.m.path.abspath(checkout.join(archive_config.get('base_path','')))
      rel_path = self.m.path.relpath(dir_part, full_base_path)
      rel_path = '' if rel_path == '.' else rel_path
      base_name = self.m.path.basename(include_path)

      if is_android_artifact:
        # We are not using a slash in the first parameter becase artifact_prefix
        # already includes the slash.
        artifact_path = '%s/%s' % (rel_path, base_name)
        # Replace ANDROID_ARTIFACTS_BUCKET to include the realm.
        old_location = '/'.join([ANDROID_ARTIFACTS_BUCKET, 'io', 'flutter'])
        new_location = '/'.join(filter(
            bool,
            [ANDROID_ARTIFACTS_BUCKET, 'io', 'flutter', artifact_realm])
        )
        artifact_path = artifact_path.replace(old_location, new_location)
        bucket_and_prefix = LUCI_TO_ANDROID_GCS_PREFIX.get(bucket)
        artifact_path = '/'.join(filter(bool, [bucket_and_prefix, artifact_path]))
      else:
        bucket_and_prefix = LUCI_TO_GCS_PREFIX.get(bucket)
        artifact_path = '/'.join(filter(bool, [bucket_and_prefix, 'flutter', artifact_realm, commit, rel_path, base_name]))

      results.append(
          ArchivePaths(
              include_path,
              'gs://%s' % artifact_path
          )
      )
    return results

  def global_generator_paths(self, checkout, archives):
    """Calculates the global generator paths for an archive config.

    Args:
      checkout: (Path) the engine repository checkout folder.
      archives: (list) list of dictionaries source and destination path
        of files relative to the gclient checkout.

    Returns:
      A list of ArchivePaths with expected local and remote locations for the
      generated artifacts.
    """
    results = []

    # Do not archive if this is a monorepo try build.
    if self.m.monorepo.is_monorepo_try_build:
      return results

    # Calculate prefix and commit.
    is_monorepo = self.m.buildbucket.gitiles_commit.project == MONOREPO
    bucket = MONOREPO if is_monorepo else self.m.buildbucket.build.builder.bucket
    if is_monorepo:
      commit = self.m.repo_util.get_commit(checkout.join('../../monorepo'))
    else:
      commit = self.m.repo_util.get_commit(checkout.join('flutter'))
    bucket_and_prefix = LUCI_TO_GCS_PREFIX.get(bucket)

    for archive in archives:
      # Artifacts bucket is calculated using the LUCI bucket but we also use the realm to upload
      # artifacts to the same bucket but different path when the build configurations use an
      # experimental realm. Defaults to experimental.
      artifact_realm = REALM_TO_PATH.get(archive.get('realm', ''), 'experimental')
      source = checkout.join(archive.get('source'))
      artifact_path = '/'.join(
          filter(
              bool, [bucket_and_prefix, 'flutter', artifact_realm, commit,
                        archive.get('destination')]
          )
      )
      dst = 'gs://%s' % artifact_path
      results.append(ArchivePaths(self.m.path.abspath(source), dst))
    return results
