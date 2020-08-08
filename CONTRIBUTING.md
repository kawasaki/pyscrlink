Contributions to the project are always welcome!
Though there is no strict rule on how to contribute, following points will help to merge your changes smoothly.
(Some of them are quote from Linux patch submit guide. :)

CODE
----
- Separate commits so that each comit has single purpose: it is good to separate "bug fix", "new feature" and "spelling fix".
- The preferred limit on the length of a single line is 80 columns.

COMMIT MESSAGE
--------------
- Write short description in the first line with format "CHANGE_TARGET: SHORT_CHANGE_DESCRIPTION",
  e.g. "BLESession: Support multiple Bluetooth adapters" or "BLESession.matches: Support namePrefix
  in matching filters".
- Describe your changes in imperative mood, e.g. "make xyzzy do frotz"
  instead of "[This patch] makes xyzzy do frotz" or "[I] changed xyzzy
  to do frotz", as if you are giving orders to the codebase to change
  its behaviour.
