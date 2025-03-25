# moodle-antivirus_encrypted

<a href="https://github.com/catalyst/moodle-antivirus_encrypted/actions">
<img src="https://github.com/catalyst/moodle-antivirus_encrypted/workflows/ci/badge.svg">
</a>

Moodle can scan different files with different virus scanners, but some virus scanners don't scan files if they can't read them.

In particular this gives you a false positive with encrypted files such as zip
files, with an option to provide a password with the file for the end user to
download and decrypt. This pseudo virus checker looks for files which have some
level of known encryption on them and fails them so that they cannot upload,
i.e. if we cannot inspect the file then we fail safe.

## Supported files
 * Zip archives
 * Libreoffice documents
 * PDF documents

### PDF information
Unfortunately the PDF specification is quite complicated and has varying levels of implementation, which can occasionally lead to incorrect encryption detection. 

PDFs can be scanned for encryption with Ghostscript (default) and/or QPDF. Ghostscript is used in other parts of Moodle so is likely already installed, but has been know to emit false positives for documents using some of the more obscure PDF features. QPDF tends to be more forgiving, but is likely not already installed. 

You can enable/disable these from the antivirus_encrypted configuration page in the Administrator settings.

## Branches

| LMS version         | Branch           | PHP |
|---------------------|------------------|-----|
| Moodle 3.3+         | master           | 7.4 |
| Totara 12+          | master           | 7.4 |

This plugin supports Moodle 3.3+ and Totara 12+. All supported versions should
use the master branch of the plugin.

## Support

If you have issues please log them in github here

https://github.com/catalyst/moodle-antivirus_encrypted/issues

Please note our time is limited, so if you need urgent support or want to
sponsor a new feature then please contact Catalyst IT Australia:

https://www.catalyst-au.net/contact-us

This plugin was developed by Catalyst IT Australia:

https://www.catalyst-au.net/

<img alt="Catalyst IT" src="https://cdn.rawgit.com/CatalystIT-AU/moodle-auth_saml2/master/pix/catalyst-logo.svg" width="400">
