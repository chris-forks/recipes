# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine import recipe_api


class RetryApi(recipe_api.RecipeApi):
  """Utilities to retry recipe steps."""

  def step(
      self,
      step_name,
      cmd,
      max_attempts=3,
      sleep=5.0,
      backoff_factor=1.5,
      **kwargs
  ):
    """Retry the step with exponential backoff.
    Args:
        step_name (str): Name of the step.
        cmd (None|List[int|string|Placeholder|Path]): The program
          arguments to run.
        max_attempts (int): How many times to try before giving up.
        sleep (int or float): The initial time to sleep between attempts.
        backoff_factor (int or float): The factor by which the sleep time
            will be multiplied after each attempt.

    Returns a `step_data.StepData` for the running step.
    """
    for attempt in range(max_attempts):
      step = self.m.step(step_name, cmd, ok_ret='any', **kwargs)
      # Show syslog and emulator_log for FEMU test suite.
      if 'Run FEMU Test Suite' in step_name:
        step.presentation.logs['syslog'] = step.raw_io.output_texts['syslog']
        step.presentation.logs['emulator_log'] = step.raw_io.output_texts[
            'emulator_log']
      if step.retcode != 0:
        if attempt == max_attempts - 1:
          step.presentation.status = self.m.step.FAILURE
          raise self.m.step.StepFailure('.'.join(step.name_tokens), step)
        self.m.time.sleep(sleep)
        sleep *= backoff_factor
      else:
        # Append an extra step to reflect test flakiness, so that we can easily
        # collect flaky test statistics. This can also be used to trigger
        # notification when a flake happens.
        # This is mainly used for Engine builders for now.
        if attempt > 0 and 'test:' in step_name:
          self.m.test_utils.flaky_step(step_name)
        return step

  def wrap(
      self,
      func,
      step_name=None,
      max_attempts=3,
      sleep=5.0,
      backoff_factor=1.5,
      retriable_codes='any',
      **kwargs
  ):
    """Retry wrapped function which needs step support.
    Args:
        step_name (str): Name of the step.
        func (callable): A function that performs the action that should be
          retried on failure. If it raises a `StepFailure`, it will be retried.
          Any other exception will end the retry loop and bubble up.
        retriable_codes ('any' or Tuple(int)): Return codes that should allow a
          retry. Pass 'any' to accept any.
        max_attempts (int): How many times to try before giving up.
        sleep (int or float): The initial time to sleep between attempts.
        backoff_factor (int or float): The factor by which the sleep time
            will be multiplied after each attempt.
    Returns:
      The result of executing func.
    """
    for attempt in range(max_attempts):
      try:
        result = func()
        # Append an extra step to reflect test flakiness, so that we can easily
        # collect flaky test statistics. This can also be used to trigger
        # notification when a flake happens.
        # This is mainly used for Engine builders for now.
        if attempt > 0 and step_name is not None and 'test:' in step_name:
          self.m.test_utils.flaky_step(step_name)
        return result
      except self.m.step.StepFailure:
        # Retrying with nested steps is not supported with retriable codes
        # different than any.
        retcode = 0
        if retriable_codes != 'any':
          step = self.m.step.active_result
          retcode = step.retcode

        retriable_failure = retriable_codes == 'any' or \
            retcode in retriable_codes
        if not retriable_failure or attempt == max_attempts - 1:
          raise
        self.m.time.sleep(sleep)
        sleep *= backoff_factor

  def basic_wrap(
      self,
      func,
      max_attempts=3,
      sleep=5.0,
      backoff_factor=1.5,
      timeout=0,
      **kwargs
  ):
    """Retry basic wrapped function without step support.
      Args:
          func (callable): A function that performs the action that should be
            retried on failure. If it raises a `StepFailure` or `InfraFailure`,
            it will be retried. Any other exception will end the retry loop and
            bubble up.
          max_attempts (int): How many times to try before giving up.
          sleep (int or float): The initial time to sleep between attempts.
          backoff_factor (int or float): The factor by which the sleep time
              will be multiplied after each attempt.
          timeout (int or float): A value passed to the `func` argument. Is
              multiplied by the `backoff_factor` after each attempt.
      Returns:
        The result of executing func.
      """
    for attempt in range(max_attempts):
      try:
        result = func(timeout=timeout)
        return result
      except (self.m.step.StepFailure, self.m.step.InfraFailure):
        if attempt == max_attempts - 1:
          raise
        self.m.time.sleep(sleep)
        sleep *= backoff_factor
        timeout *= backoff_factor

  def run_flutter_doctor(self):
    self.step(
        'flutter doctor',
        ['flutter', 'doctor', '--verbose'],
        max_attempts=3,
        timeout=300,
    )
