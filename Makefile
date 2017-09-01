check:
	set -o pipefail && xcodebuild test -project PGPFormat.xcodeproj -scheme PGPFormatTests -destination 'platform=iOS Simulator,name=iPhone 7' | tee xcodebuild.log | xcpretty
