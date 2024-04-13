.PHONY: phony
phony: setup_keychain.sh
	rm -f password p12 p12.p12
	echo 'secrets' > p12
	echo 'my password' > password
	touch dart_codesign_binary
	FLUTTER_P12_PASSWORD=password \
	FLUTTER_P12=p12 \
	P12_SUFFIX_FILEPATH=p12.p12 \
	SETUP_KEYCHAIN_LOGS_PATH=logs.txt \
	CODESIGN_PATH=dart_codesign_binary \
	./setup_keychain.sh
