_LNG=$(LANGUAGE)
_INX=.
STAMP=stampinf -f $@ -a $(_BUILDARCH) -v $(USBPCAP_VERSION)

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx
    copy $(_INX)\$(@B).inx $@
    $(STAMP)