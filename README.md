# moodle-antivirus_encrypted

Moodle can scan different files with different virus scanners, but some virus scanners don't scan files if they can't read them.

In particular this gives you a false positive with files which have been encrypted such as zip files, and a password could be provided with the file for the end user to download and decrypt. This pseudo virus checker simply looks for files which have some level of known encryption on them and fails them so that they cannot be uploaded, ie if they file cannot be inspected them we fail safe.
