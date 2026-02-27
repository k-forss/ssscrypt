# Recording a Demo

Use [asciinema](https://asciinema.org/) to record terminal sessions for the README.

## Install

```bash
# Arch
sudo pacman -S asciinema

# Ubuntu/Debian
sudo apt install asciinema

# macOS
brew install asciinema
```

## Record

```bash
# Start recording
asciinema rec demo.cast --title "ssscrypt: encrypt + decrypt roundtrip"

# Inside the recording, run:
echo "top secret root key" > /tmp/demo-secret.txt

ssscrypt encrypt --in /tmp/demo-secret.txt --out /tmp/demo-secret.enc \
  --threshold 2 -n 3 --new-shares-dir /tmp/demo-shares/

ls /tmp/demo-shares/

ssscrypt decrypt --in /tmp/demo-secret.enc --out /tmp/demo-recovered.txt \
  --shares-dir /tmp/demo-shares/

diff /tmp/demo-secret.txt /tmp/demo-recovered.txt && echo "✓ roundtrip OK"

# Clean up
rm -rf /tmp/demo-secret.txt /tmp/demo-secret.enc /tmp/demo-recovered.txt /tmp/demo-shares/

# Press Ctrl-D or type 'exit' to stop recording
```

## Upload & embed

```bash
# Upload to asciinema.org
asciinema upload demo.cast

# Or convert to SVG for README embedding
# Install svg-term: npm install -g svg-term-cli
svg-term --in demo.cast --out demo.svg --window --width 80 --height 24
```

Then add to README:

```markdown
## Demo

[![asciicast](https://asciinema.org/a/YOUR_ID.svg)](https://asciinema.org/a/YOUR_ID)
```

## Tips

- Keep recordings short (< 60 seconds)
- Use `--idle-time-limit 2` to cap idle pauses
- Run from a clean temp directory so paths are simple
- Consider `asciinema rec --overwrite demo.cast` to re-record
