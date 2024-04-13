#!/usr/bin/env dart

// Helper script to import a flutter p12 identity.

import 'dart:io' as io;

const String keychainName = 'build.keychain';
const String keychainPassword = '';
const int totalRetryAttempts = 3;

Future<void> main() async {
  final io.File logFile = io.File(io.Platform.environment['SETUP_KEYCHAIN_LOGS_PATH']!);
  final logSink = logFile.openWrite();
  void log(String line) {
    logSink.writeln('$line\n');
  }

  int exitCode = 1;
  try {
    exitCode = await innerMain(
      passwordPath: io.Platform.environment['FLUTTER_P12_PASSWORD']!,
      flutterP12Path: io.Platform.environment['FLUTTER_P12']!,
      p12SuffixFilePath: io.Platform.environment['P12_SUFFIX_FILEPATH']!,
      codesignPath: io.Platform.environment['CODESIGN_PATH']!,
      log: log,
    );
  } finally {
    await logSink.flush();
    await logSink.close();
  }
  io.exit(exitCode);
}

Future<int> innerMain({
  required String passwordPath,
  required String flutterP12Path,
  required String p12SuffixFilePath,
  required String codesignPath,
  required void Function(String) log,
}) async {
  String security(List<String> args) {
    log('Executing ${<String>['/usr/bin/security', ...args]}');

    final io.ProcessResult result =
        io.Process.runSync('/usr/bin/security', args);

    log('process finished with exitCode ${result.exitCode}');
    log('STDOUT:\n\n${result.stdout}');
    log('STDERR:\n\n${result.stderr}');

    if (result.exitCode != 0) {
      throw io.ProcessException(
          '/usr/bin/security', args, 'failed', result.exitCode);
    }

    return result.stdout as String;
  }

  final String rawPassword = io.File(passwordPath).readAsStringSync();

  // Only filepath with a .p12 suffix will be recognized
  io.File(flutterP12Path).renameSync(p12SuffixFilePath);

  // Delete build.keychain if it exists
  security(const <String>['delete-keychain', keychainName]);

  // Create keychain.
  security(const <String>[
    'create-keychain',
    '-p',
    keychainPassword,
    keychainName,
  ]);

  // Retrieve current list of keychains on the search list of current machine.
  final keychains = security(const <String>['list-keychains', '-d', 'user'])
      .split('\n')
      .map<String?>((String line) {
    final RegExp pattern = RegExp(r'^\s*".*\/([a-zA-Z0-9.]+)-db"');
    final RegExpMatch? match = pattern.firstMatch(line);
    if (match == null) {
      return null;
    }
    // The first (and only) capture group is the name of the keychain
    return match.group(1);
  }).whereType<String>();

  print('User keychains on this machine: $keychains');

  // Add keychain name to search list.
  // Without this, future commands such as `security import`,
  // `security find-identity` and `codesign ...` will fail to find the cert
  // in our newly created keychain.
  security(<String>[
    '-v',
    'list-keychains',
    // TODO(fujino): we probably don't need $keychains here, only keychainName should be required
    '-s', ...keychains, keychainName,
  ]);

  // Set $keychainName as default.
  security(<String>[
    'default-keychain',
    '-s',
    keychainName,
  ]);

  // Unlock keychainName to allow sign commands to use its certs.
  security(<String>['unlock-keychain', '-p', keychainPassword, keychainName]);

  // This will be exponentially increased on retries
  int sleepSeconds = 2;

  for (int attempt = 0; attempt < totalRetryAttempts; attempt++) {
    security(<String>[
      'import',
      p12SuffixFilePath,
      '-k', keychainName,
      '-P', rawPassword,
      // -T allows the specified program to access this identity
      '-T', codesignPath,
      '-T', '/usr/bin/codesign',
    ]);
    security(<String>[
      'set-key-partition-list',
      '-S',
      'apple-tool:,apple:,codesign:',
      '-s',
      '-k',
      '',
      keychainName,
    ]);

    final String identities =
        security(const <String>['find-identity', '-v', keychainName]);
    if (identities.contains('FLUTTER.IO LLC')) {
      log('successfully found a Flutter identity in the $keychainName keychain');
      return 0;
    }
    log('failed to find a Flutter identity in the $keychainName keychain on attempt $attempt');
    await Future<void>.delayed(Duration(seconds: sleepSeconds));
    sleepSeconds *= sleepSeconds;
  }
  log('failed to find a Flutter identity after $totalRetryAttempts attempts.');
  return 1;
}
