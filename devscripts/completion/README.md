## Generating shell completions

```shell
# Create virtual environment and install fdroidserver
python3 -m venv --system-site-packages venv
# Adjust this if you use a different shell than Bash
. venv/bin/activate
pip install .

# Preview completions for fish
python3 devscripts/completion/fish-completion.py

# Write completions for fish
python3 devscripts/completion/fish-completion.py > completions/fish-completion.fish
```
