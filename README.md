# moodle-antivirus_encrypted

Moodle can scan different files with different virus scanners, but some virus scanners don't scan files if they can't read them.

In particular this gives you a false positive with files which have been encrypted such as zip files, and a password could be provided with the file for the end user to download and decrypt. This pseudo virus checker simply looks for files which have some level of known encryption on them and fails them so that they cannot be uploaded, ie if they file cannot be inspected then we fail safe.

## Currently supported files
 * Zip archives
 * Libreoffice documents
 * PDF documents

## Branches

This plugin is currently supported back to Moodle 3.3 - Totara 12. All supported versions should use the master branch of the plugin.

## Support

If you have issues please log them in github here

https://github.com/catalyst/moodle-antivirus_encrypted/issues

Please note our time is limited, so if you need urgent support or want to
sponsor a new feature then please contact Catalyst IT Australia:

https://www.catalyst-au.net/contact-us

This plugin was developed by Catalyst IT Australia:

https://www.catalyst-au.net/

<img alt="Catalyst IT" src="https://cdn.rawgit.com/CatalystIT-AU/moodle-auth_saml2/master/pix/catalyst-logo.svg" width="400">
