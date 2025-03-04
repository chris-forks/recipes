# Copyright 2021 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Flutter Engine tester recipe.

This recipe is used to run tests using prebuilt artifacts.
"""

DEPS = [
    'flutter/flutter_deps',
    'flutter/monorepo',
    'flutter/os_utils',
    'flutter/repo_util',
    'flutter/retry',
    'recipe_engine/buildbucket',
    'recipe_engine/context',
    'recipe_engine/file',
    'recipe_engine/json',
    'recipe_engine/path',
    'recipe_engine/properties',
    'recipe_engine/step',
]

SAMPLE_MONOREPO_COMMITS = {
    "engine/src/flutter": "57ac2d3d67bde512ed071d0250bfdcb986142ea4",
    "engine/src/third_party/dart": "355295789e4dee435d6ae2dff3d38dc1d5a9ab9a",
    "flutter": "523b600efeb7d60b743c1b952201aa969a744791"
}


def get_monorepo_framework(api):
  monorepo = api.path['cache'].join('builder', 'monorepo')
  api.repo_util.checkout('monorepo', monorepo)
  commits = api.file.read_json(
      'get commits from monorepo',
      monorepo.join('commits.json'),
      test_data=SAMPLE_MONOREPO_COMMITS,
      include_log=True
  )
  return commits['flutter']


def RunSteps(api):
  # Collect memory/cpu/process before task execution.
  api.os_utils.collect_os_info()
  builder = api.path['cache'].join('builder')
  flutter = builder.join('flutter')
  if api.monorepo.is_monorepo_try_build:
    framework_ref = 'refs/heads/main'
    artifact_url = 'https://storage.googleapis.com/flutter_archives_v2/monorepo_try'
    engine_version = api.monorepo.try_build_identifier
  elif api.monorepo.is_monorepo_ci_build:
    framework_ref = get_monorepo_framework(api)
    artifact_url = 'https://storage.googleapis.com/flutter_archives_v2/monorepo'
    engine_version = api.buildbucket.gitiles_commit.id
  else:
    framework_ref = 'refs/heads/master'
    artifact_url = 'https://storage.googleapis.com/flutter_archives_v2'
    engine_version = api.buildbucket.gitiles_commit.id
  api.repo_util.checkout('flutter', flutter, ref=framework_ref)
  api.file.write_text(
      'update engine version',
      flutter.join('bin', 'internal', 'engine.version'), engine_version + '\n'
  )

  # TODO(https://github.com/flutter/flutter/issues/116906): Combine this
  # recipe with the flutter/flutter_drone recipe if possible, to avoid
  # duplication.
  env, env_prefixes = api.repo_util.flutter_environment(flutter)
  test_config = api.properties.get('build')
  deps = test_config.get('test_dependencies', [])
  api.flutter_deps.required_deps(env, env_prefixes, deps)
  shard = test_config.get('shard')
  subshard = test_config.get('subshard')
  env['SHARD'] = shard
  env['SUBSHARD'] = subshard
  if subshard:
    shard_name = '%s %s' % (shard, subshard)
  else:
    shard_name = shard
  env['FLUTTER_STORAGE_BASE_URL'] = artifact_url
  with api.context(env=env, env_prefixes=env_prefixes, cwd=flutter):
    api.retry.step(
        'download dependencies', ['flutter', 'update-packages', '-v'],
        max_attempts=2,
        infra_step=True
    )
    api.step(
        'Run %s tests' % shard_name,
        [flutter.join('bin', 'dart'),
         flutter.join('dev', 'bots', 'test.dart')]
    )
  # This is to clean up leaked processes.
  api.os_utils.kill_processes()
  # Collect memory/cpu/process after task execution.
  api.os_utils.collect_os_info()


def GenTests(api):
  build = {'shard': 'framework_coverage'}
  yield api.test(
      'monorepo',
      api.properties(build=build, no_goma=True),
      api.monorepo.ci_build(),
      api.step_data(
          'get commits from monorepo',
          api.file.read_json(SAMPLE_MONOREPO_COMMITS)
      ),
  )

  yield api.test(
      'monorepo_tryjob',
      api.properties(
          build=build, no_goma=True, try_build_identifier='81123491'
      ),
      api.monorepo.try_build(),
  )

  yield api.test(
      'engine',
      api.properties(build=build, no_goma=True),
      api.buildbucket.ci_build(
          project='flutter',
          bucket='prod',
          builder='linux-host',
          git_repo='https://flutter.googlesource.com/mirrors/engine',
          git_ref='refs/heads/main',
          revision='abcd' * 10,
          build_number=123,
      ),
  )

  web_tests_subshard_build = {
      'shard':
          'web_tests',
      'subshard':
          '3',
      'test_dependencies': [{
          "dependency": "chrome_and_driver", "version": "version:96.2"
      }],
  }

  yield api.test(
      'monorepo_web_tests',
      api.properties(build=web_tests_subshard_build, no_goma=True),
      api.monorepo.ci_build(),
      api.step_data(
          'get commits from monorepo',
          api.file.read_json(SAMPLE_MONOREPO_COMMITS)
      ),
  )

  framework_tests_subshard_build = {
      'shard':
          'framework_tests',
      'subshard':
          'slow',
      'test_dependencies': [{
          "dependency": "android_sdk", "version": "version:33v6"
      }],
  }

  yield api.test(
      'monorepo_framework_tests',
      api.properties(build=framework_tests_subshard_build, no_goma=True),
      api.monorepo.ci_build(),
      api.step_data(
          'get commits from monorepo',
          api.file.read_json(SAMPLE_MONOREPO_COMMITS)
      ),
  )
