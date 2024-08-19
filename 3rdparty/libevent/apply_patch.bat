@echo off
git apply --reverse --ignore-whitespace %1
cmd /c "exit /b 0"
git apply %1
