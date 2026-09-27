!macro NSIS_HOOK_PREUNINSTALL
  ; A quiet update replaces the files and must not ask about rules or remove
  ; the logon task. A real uninstall asks, and always removes the task.
  IfSilent done
  MessageBox MB_YESNO|MB_ICONQUESTION "Remove the firewall rules WattWall added?$\r$\n$\r$\nNo leaves those blocks in place. The logon task is removed either way." /SD IDNO IDYES removeRules
  ExecWait '"$INSTDIR\WattWall.exe" --remove-task'
  Goto done
  removeRules:
    ExecWait '"$INSTDIR\WattWall.exe" --cleanup'
  done:
!macroend
