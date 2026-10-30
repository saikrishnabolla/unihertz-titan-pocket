#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p test-classes
find src stubs test -name '*.java' -print > test-sources.txt
/opt/homebrew/opt/openjdk@17/bin/javac --release 8 -Xlint:all -Werror -d test-classes @test-sources.txt
/opt/homebrew/opt/openjdk@17/bin/java -cp test-classes com.android.server.input.LegacyKeyboardLightBridgeTest
/opt/homebrew/opt/openjdk@17/bin/java -cp test-classes com.android.server.input.LegacyKeyboardLightPolicyTest
mkdir -p production-classes
/opt/homebrew/opt/openjdk@17/bin/javac --release 8 -Xlint:all -Werror -classpath test-classes -sourcepath src -d production-classes src/com/android/server/input/LegacyKeyboardLightBridge.java src/com/android/server/input/LegacyKeyboardLightPolicy.java
python3 - <<'PY'
from pathlib import Path
import hashlib
root = Path(__file__).resolve().parent
policy = root / 'src/com/android/server/input/LegacyKeyboardLightPolicy.java'
assert hashlib.sha256(policy.read_bytes()).hexdigest() == '22c397d01f11c696cf17eb3e8febe92932d6aee4717fd684b8ab763b3f9ad899'
classes = sorted(str(p.relative_to(root / 'production-classes')) for p in (root / 'production-classes').rglob('*.class'))
assert classes == ['com/android/server/input/' + name + '.class' for name in [
    'LegacyKeyboardLightBridge$1', 'LegacyKeyboardLightBridge$2', 'LegacyKeyboardLightBridge',
    'LegacyKeyboardLightPolicy$Clock', 'LegacyKeyboardLightPolicy$Result',
    'LegacyKeyboardLightPolicy$Sink', 'LegacyKeyboardLightPolicy']]
(root / 'production-classfiles.txt').write_text('\n'.join(classes) + '\n')
print('PASS production classfiles contain only bridge/policy; retained policy source unchanged')
PY
