# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from PB.recipe_modules.recipe_engine.swarming import properties
from recipe_engine.post_process import DoesNotRun, Filter, StatusFailure

DEPS = [
    'flutter/test_utils',
    'recipe_engine/platform',
    'recipe_engine/properties',
    'recipe_engine/raw_io',
]


def RunSteps(api):
  api.test_utils.run_test('mytest', ['ls', '-la'])
  api.test_utils.test_step_name('test')
  api.test_utils.flaky_step('test step')
  env = {}
  env_prefixes = {}
  target_tags = api.properties.get("tags")
  api.test_utils.collect_benchmark_tags(env, env_prefixes, target_tags)


def GenTests(api):
  yield api.test(
      'passing',
      api.properties(fake_data='#success\nthis is a success'),
      api.platform.name('win'),
      api.properties(tags=['hostonly']),
  )
  yield api.test(
      'passing-mac', api.platform.name('mac'), api.properties(tags=['ios']),
      api.properties(fake_data='#success\nthis is a success'),
      api.step_data(
          'Find device type',
          stdout=api.raw_io.output_text('iPhone8,1'),
      )
  )
  yield api.test(
      'flaky', api.properties(tags=['hostonly', 'android']),
      api.properties(fake_data='#flaky\nthis is a flaky\nflaky: true'),
      api.platform.name('linux')
  )
  yield api.test(
      'failing',
      api.step_data('mytest', retcode=1),
      api.properties(fake_data='#failure\nthis is a failure'),
      status='FAILURE'
  )
  very_long_string = "xyz\n" * 1500
  yield api.test(
      'long_stdout',
      api.step_data('mytest', retcode=1),
      api.properties(fake_data=very_long_string),
      status='FAILURE'
  )
