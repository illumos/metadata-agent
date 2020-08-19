#!/bin/bash

. /lib/svc/share/smf_include.sh

USERSCRIPT=/var/metadata/userscript

if [[ -z "$SMF_FMRI" ]]; then
	printf 'ERROR: SMF_FMRI not set; running under SMF?\n' >&2
	exit "$SMF_EXIT_ERR_FATAL"
fi

#
# Check to see if the metadata service obtained a metadata script:
#
if [[ ! -x "$USERSCRIPT" ]]; then
	#
	# There is no script.  Disable this service and signal success.
	#
	/usr/sbin/svcadm disable "$SMF_FMRI"
	exit "$SMF_EXIT_OK"
fi

#
# Run the script.
#
if ! "$USERSCRIPT"; then
	#
	# Exit 1 so that SMF might restart us.
	#
	exit 1
fi

#
# The script was successful.  Remove it so that it does not run again.
#
if ! /bin/rm -f "$USERSCRIPT"; then
	printf 'ERROR: could not remove userscript file?\n' >&2
	exit 1
fi

#
# Everything completed successfully.  Disable this service and signal success.
#
/usr/sbin/svcadm disable "$SMF_FMRI"
exit "$SMF_EXIT_OK"
