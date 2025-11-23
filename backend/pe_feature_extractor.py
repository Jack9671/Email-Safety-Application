"""
PE File Feature Extractor for Malware Detection
Extracts exactly 1000 features from Windows PE files compatible with XGBoost model
"""

import pefile
import hashlib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional
import joblib
import warnings
warnings.filterwarnings('ignore')


class PEFeatureExtractor:
    """Extract 1000 features from PE files for malware classification"""
    
    # Complete list of 443 DLLs (from document)
    DLL_LIST = ['shlwapi.dll', 'msvcp60.dll', 'msvbvm60.dll', 'kernel32.dll', 'msvcp90.dll', 'version.dll', 'wininet.dll', 'cabinet.dll', 'crypt32.dll', 'gdi32.dll', 'oledlg.dll', 'libglib-2.0-0.dll', 'uxtheme.dll', 'user32.dll', 'advapi32.dll', 'mfc140.dll', 'msvcrt.dll', 'oleacc.dll', 'shell32.dll', 'psapi.dll', 'ntdll.dll', 'mscoree.dll', 'ole32.dll', 'windowscodecs.dll', 'comctl32.dll', 'pdh.dll', 'wsock32.dll', 'rpcrt4.dll', 'shfolder.dll', 'appvisvsubsystems32.dll', 'mfc42.dll', 'wtsapi32.dll', 'loadperf.dll', 'comdlg32.dll', 'secur32.dll', 'vcruntime140.dll', 'oleaut32.dll', 'ws2_32.dll', 'winmm.dll', 'iphlpapi.dll', 'winhttp.dll', 'gdiplus.dll', 'resutils.dll', 'setupapi.dll', 'imm32.dll', 'msimg32.dll', 'api-ms-win-core-processthreads-l1-1-0.dll', 'winspool.drv', 'url.dll', 'urlmon.dll', 'netapi32.dll', 'msvcr90.dll', 'opengl32.dll', 'api-ms-win-core-sysinfo-l1-1-0.dll', 'odbc32.dll', 'mpr.dll', 'msys-crypto-1.0.0.dll', 'msys-ssl-1.0.0.dll', 'unattend.dll', 'actionqueue.dll', 'api-ms-win-core-privateprofile-l1-1-1.dll', 'nodewinrtwrap.dll', 'api-ms-win-downlevel-kernel32-l2-1-0.dll', 'api-ms-win-power-setting-l1-1-0.dll', 'combase.dll', 'api-ms-win-core-threadpool-legacy-l1-1-0.dll', 'omadmapi.dll', 'dmxmlhelputils.dll', 'wwapi.dll', 'dhcpcsvc.dll', 'dhcpcsvc6.dll', 'api-ms-win-eventing-legacy-l1-1-0.dll', 'api-ms-win-core-file-l2-1-2.dll', 'wsmsvc.dll', 'certca.dll', 'certenroll.dll', 'api-ms-win-eventing-consumer-l1-1-0.dll', 'dnsapi.dll', 'maintenanceui.dll', 'dmpushproxy.dll', 'dmcmnutils.dll', 'dsclient.dll', 'nvsmartmax.dll', 'esscli.dll', 'nvsmartmax64.dll', 'sourcecontrol.dll', 'zlibwapi.dll', 'wtli.dll', 'cpfe.dll', 'jxbrowser-chromium-lib.dll', 'lua51.dll', 'galaxy.dll', 'ter32.dll', 'tier0.dll', 'vstdlib.dll', 'qtcore4.dll', 'qtgui4.dll', 'steam_api64.dll', 'qt5designer.dll', 'qt5xml.dll', 'qt5network.dll', 'qt5quick.dll', 'qt5qml.dll', 'avrt.dll', 'sensapi.dll', 'statreport.dll', 'msys-magic-1.dll', 'mvm.dll', 'oemuninstall.dll', 'perl516.dll', 'php5ts.dll', 'python27.dll', 'qt5dbus.dll', 'qt5designercomponents.dll', 'kbdit.dll', 'kbdkyr.dll', 'msdmo.dll', 'msident.dll', 'libsybdb-5.dll', 'libut.dll', 'uiw.dll', 'libvlc.dll', 'libpoppler-glib-8.dll', 'api-ms-win-security-audit-l1-1-1.dll', 'api-ms-win-security-sddlparsecond-l1-1-0.dll', 'avicap32.dll', 'browseui.dll', 'ddraw.dll', 'icmp.dll', 'ipsecsnp.dll', 'appobj.dll', 'icutu57.dll', 'icuin57.dll', 'icuuc57.dll', 'cryptsp.dll', 'wer.dll', 'api-ms-win-core-file-l1-2-2.dll', 'nvml.dll', 'apphelp.dll', 'api-ms-win-core-localization-l1-2-2.dll', 'api-ms-win-core-localization-private-l1-1-0.dll', 'appxalluserstore.dll', 'msvcdis110.dll', 'perl524.dll', 'libjasper-4.dll', 'tapi32.dll', 'wlanapi.dll', 'dwmapi.dll', 'wbemcomn.dll', 'msports.dll', 'occache.dll', 'panmap.dll', 'ulib.dll', 'winscard.dll', 'vmwarecui.dll', 'vmwarestring.dll', 'vmwarewui.dll', 'vixdiskmountapi.dll', 'gobject-2.0.dll', 'gvmomi.dll', 'vmappcfg.dll', 'msvcm90.dll', 'dmcommandlineutils.dll', 'ppcore.dll', 'glib-2.0.dll', 'sigc-2.0.dll', 'vmapputil.dll', 'vmclientcore.dll', 'vmdbcom.dll', 'vmwarebase.dll', 'libxml2-2.dll', 'libzmq.dll', 'mfc90u.dll', 'msvcr80.dll', 'msvcp_win.dll', 'api-ms-win-crt-private-l1-1-0.dll', 'ext-ms-win-com-ole32-l1-1-1.dll', 'ext-ms-win-shell-shell32-l1-2-0.dll', 'dwrite.dll', 'd2d1.dll', 'mscms.dll', 'xolehlp.dll', 'ntlanman.dll', 'mprapi.dll', 'dispex.dll', 'iassdo.dll', 'kbdfi.dll', 'kbdic.dll', 'kbdno.dll', 'midimap.dll', 'mspatcha.dll', 'ntmarta.dll', 'shdocvw.dll', 'webclnt.dll', 'dbnetlib.dll', 'dbnmpntw.dll', 'filemgmt.dll', 'iasacct.dll', 'iepeers.dll', 'inetcomm.dll', 'inseng.dll', 'kbdal.dll', 'actxprxy.dll', 'adsnt.dll', 'avifil32.dll', 'catsrvps.dll', 'certcli.dll', 'certmgr.dll', 'console.dll', 'd3dxof.dll', 'kbdbe.dll', 'kbdhe319.dll', 'kbdlt1.dll', 'kbdusl.dll', 'msctf.dll', 'msls31.dll', 'themeui.dll', 'usp10.dll', 'query.dll', 'winrnr.dll', 'msvidctl.dll', 'cdosys.dll', 'docprop.dll', 'efsadu.dll', 'fontsub.dll', 'icmui.dll', 'msisip.dll', 'sqlsrv32.dll', 'activeds.dll', 'httpapi.dll', 'sfc.dll', 'ktmw32.dll', 'comsvcs.dll', 'kbdir.dll', 'icm32.dll', 'kbdlv1.dll', 'odbccu32.dll', 'sfc_os.dll', 'w32topl.dll', 'kbdcan.dll', 'kbdhe.dll', 'kbdycl.dll', 'api-ms-win-core-localization-l1-2-0.dll', 'api-ms-win-core-errorhandling-l1-1-0.dll', 'api-ms-win-core-processthreads-l1-1-1.dll', 'api-ms-win-core-interlocked-l1-1-0.dll', 'api-ms-win-core-debug-l1-1-0.dll', 'api-ms-win-core-rtlsupport-l1-1-0.dll', 'api-ms-win-core-file-l1-1-0.dll', 'api-ms-win-core-heap-l1-1-0.dll', 'dhcpsapi.dll', 'iscsidsc.dll', 'msrating.dll', 'rpcns4.dll', 'rtm.dll', 'wow32.dll', 'api-ms-win-core-memory-l1-1-0.dll', 'api-ms-win-core-console-l3-2-0.dll', 'msimtf.dll', 'oleprn.dll', 'pstorec.dll', 'api-ms-win-crt-multibyte-l1-1-0.dll', 'msvfw32.dll', 'hhctrl.ocx', 'glu32.dll', 'clfsw32.dll', 'wship6.dll', 'zipfldr.dll', 'msacm32.dll', 'webservices.dll', 'normaliz.dll', 'wsnmp32.dll', 'mf.dll', 'adsldpc.dll', 'libisl-10.dll', 'libgnutls-30.dll', 'libhogweed-4.dll', 'libiconv-2.dll', 'libnettle-6.dll', 'libpcreposix-0.dll', 'libgsl-19.dll', 'libhdf5_hl-9.dll', 'librsvg-2-2.dll', 'gsdll64.dll', 'libwebkitgtk-1.0-0.dll', 'libmng-1.dll', 'libgthread-2.0-0.dll', 'libgmodule-2.0-0.dll', 'libglpk-40.dll', 'libgmp-10.dll', 'api-ms-win-core-sysinfo-l1-2-0.dll', 'dbgeng.dll', 'd3d11.dll', 'zlib1.dll', 'api-ms-win-ntuser-sysparams-l1-1-0.dll', 'odbccp32.dll', 'api-ms-win-crt-environment-l1-1-0.dll', 'api-ms-win-core-memory-l1-1-3.dll', 'api-ms-win-core-datetime-l1-1-0.dll', 'api-ms-win-core-psapi-ansi-l1-1-0.dll', 'api-ms-win-core-fibers-l1-1-0.dll', 'api-ms-win-core-file-l2-1-0.dll', 'libeay32.dll', 'bugsplat.dll', 'libssl-1_1.dll', 'liboctave-4.dll', 'liboctinterp-4.dll', 'liboctgui-2.dll', 'libpq.dll', 'libproj-12.dll', 'libpstoedit-0.dll', 'libqhull-5.dll', 'libhdf5-9.dll', 'libhttpd.dll', 'libaprutil-1.dll', 'libapr-1.dll', 'libwinpthread-1.dll', 'libtermcap.dll', 'libmwi18n.dll', 'libnetcdf-7.dll', 'liblcms2-2.dll', 'libpng16-16.dll', 'libxpm-nox4.dll', 'libwmf-0-2-7.dll', 'libwmflite-0-2-7.dll', 'libgimpmath-2.0-0.dll', 'libgdk_pixbuf-2.0-0.dll', 'libcairo-2.dll', 'libgdk-win32-2.0-0.dll', 'libpango-1.0-0.dll', 'libpangocairo-1.0-0.dll', 'libgimpconfig-2.0-0.dll', 'libgio-2.0-0.dll', 'libgeos_c-1.dll', 'libgeotiff-2.dll', 'libtiff-5.dll', 'libgettextlib-0-19-5-1.dll', 'libgimpui-2.0-0.dll', 'libgimpwidgets-2.0-0.dll', 'libgobject-2.0-0.dll', 'libgtk-win32-2.0-0.dll', 'libcrypto-1_1.dll', 'zlib.dll', 'yaml.dll', 'libcurl-4.dll', 'libdbus-1-3.dll', 'libexpat-1.dll', 'libfontconfig-1.dll', 'libfreetype-6.dll', 'commonlib.dll', 'pluginkernel.dll', 'filesystem.dll', 'versionmodule.dll', 'difxapi.dll', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'sqlite3.dll', 'olmapi32.dll', 'scnpst32.dll', 'scnpst64.dll', 'sfbappsdk.dll', 'shcore.dll', 'fd.dll', 'oisapp.dll', 'newdev.dll', 'crtdll.dll', 'appwiz.cpl', 'libgimp-2.0-0.dll', 'libgimpbase-2.0-0.dll', 'libgimpcolor-2.0-0.dll', 'libexif-12.dll', 'libintl-8.dll', 'libjpeg-8.dll', 'sysdm.cpl', 'cdlmso.dll', 'devobj.dll', 'libreadline6.dll', 'sqlite.dll', 'avcodec-56.dll', 'avdevice-56.dll', 'avfilter-5.dll', 'avformat-56.dll', 'qt5core.dll', 'hha.dll', 'imagehlp.dll', 'jail_container.dll', 'libmwms.dll', 'libmwservices.dll', 'java_launcher.dll', 'olepro32.dll', 'hid.dll', 'qt5printsupport.dll', 'qt5widgets.dll', 'qt5gui.dll', 'fileloader.dll', 'dibmodule.dll', 'ggspawn.dll', 'ggdownloader.dll', 'zip7module.dll', 'ssleay32.dll', 'game.dll', 'widget.dll', 'crlutl.dll', 'crli18n.dll', 'crlctl.dll', 'crlutils.dll', 'mfc120u.dll', 'crlcomponent.dll', 'chrome_elf.dll', 'sdl.dll', 'xinput1_3.dll', 'dinput8.dll', 'pthreadvse2.dll', 'lz32.dll', 'crashreport.dll', 'engine.dll', 'libz.dll', 'api-ms-win-core-registry-l2-2-0.dll', 'api-ms-win-core-shlwapi-obsolete-l1-2-0.dll', 'pocofoundation64.dll', 'libprotobuf.dll', 'avresample-2.dll', 'avutil-54.dll', 'postproc-53.dll', 'swresample-1.dll', 'swscale-3.dll', 'pgodb110.dll', 'wevtapi.dll', 'sti.dll', 'api-ms-win-core-threadpool-private-l1-1-0.dll', 'api-ms-win-core-delayload-l1-1-1.dll', 'api-ms-win-crt-time-l1-1-0.dll', 'api-ms-win-crt-runtime-l1-1-0.dll', 'api-ms-win-crt-filesystem-l1-1-0.dll', 'api-ms-win-crt-stdio-l1-1-0.dll', 'api-ms-win-crt-string-l1-1-0.dll', 'api-ms-win-crt-convert-l1-1-0.dll', 'api-ms-win-core-threadpool-l1-2-0.dll', 'api-ms-win-core-windowserrorreporting-l1-1-0.dll', 'api-ms-win-service-winsvc-l1-2-0.dll', 'api-ms-win-service-core-l1-1-1.dll', 'api-ms-win-core-sidebyside-l1-1-0.dll', 'api-ms-win-core-registry-l1-1-1.dll']

    
    # Complete list of 460 API functions (from document)
    API_FUNCTIONS = ['eventsinkaddref', 'getmessagea', 'cryptacquirecontexta', 'strxfrm', 'exit', 'polyline', 'virtualalloc', 'isiconic', 'imagelistgetimagecount', 'drawtexta', 'vbaaryunlock', 'isbadcodeptr', 'getwindowextex', 'getconsolecp', 'fprintf', 'messageboxindirecta', 'memcmp', 'imagelistsetdragcursorimage', 'regenumkeya', '1basicstringduchartraitsdstdvallocatord2stdqaexz', 'getshortpathnamea', 'imagelistaddmasked', 'findtextw', 'loadcursora', 'ciatan', 'loadcursorfromfilea', 'cryptgenkey', 'beginthreadex', 'heapcreate', 'imagelistremove', 'virtualallocex', 'wcschr', 'getmodulefilenamew', 'iobfunc', 'extcreatepen', 'getkeynametexta', 'setlasterror', 'pinitenv', 'printdlgexw', 'safearraycreate', 'isthemeactive', 'getbrushorgex', 'setwindowextex', 'getenhmetafilebits', 'printf', 'cryptdestroykey', 'escape', 'getdiskfreespacea', 'rtlcomparememory', 'heapvalidate', 'cogetobject', 'showwindow', 'regqueryvalueexw', 'messageboxindirectw', 'getprocessmemoryinfo', 'isbadreadptr', 'getcurrentthreadid', 'rtlpctofileheader', 'localfree', 'getclientrect', 'vbafreevarlist', 'getvolumeinformationa', 'codisconnectobject', 'interlockedcompareexchange', 'k32getperformanceinfo', 'getconsoletitlew', 'sethandlecount', 'vbavarvargnofree', 'setapptype', 'virtualprotect', 'imagelistgeticonsize', 'getsystemwow64directorya', 'getfileversioninfow', 'enumlanguagegrouplocalesw', 'shgetspecialfolderlocation', 'setupqueuedeletesectionw', 'combinergn', 'controlservice', 'corexemain', 'getdc', 'preparetape', 'defmdichildproca', 'checkradiobutton', 'getlasterror', 'setfilepointer', 'loadicona', 'tlsalloc', 'loadacceleratorsw', 'loadstringw', 'gdipcreatehbitmapfrombitmap', 'getkeyboardstate', 'charnexta', 'freeconsole', 'loadlibrarya', 'setcursor', 'setconsoletitlew', 'verqueryvaluea', 'varbstrfromdec', 'pathremovefilespecw', 'gdigetbatchlimit', 'getwindowlonga', 'debugbreak', 'resetwritewatch', 'multibytetowidechar', 'addaccessallowedace', 'interlockeddecrement', 'findnextvolumea', 'vbar4var', 'iidfromstring', 'rtlunwindex', 'winhttpcheckplatform', 'getstockobject', 'argv', 'tlsgetvalue', 'replacefilea', 'cexit', 'cancelwaitabletimer', 'variantinit', 'setenvironmentvariablew', 'cryptgenrandom', 'heapcompact', 'memset', 'setbkcolor', 'safearrayptrofindex', 'virtualquery', 'findnextvolumemountpointw', 'exitprocess', 'updatewindow', 'gethandleinformation', 'cspecifichandler', 'loadlibraryexa', 'pathquotespacesw', 'translatemessage', 'cryptgethashparam', 'lockservicedatabase', 'imagelistcreate', 'currentexception', 'wcmdln', 'vbanew2', 'shellexecutea', 'unmapviewoffile', 'deleteservice', 'openservicea', 'initterm', 'tlsfree', 'getstartupinfow', 'textoutw', 'gdipcreatebitmapfromstreamicm', 'getconsolealiasesa', 'getprocessworkingsetsize', 'entercriticalsection', 'heapalloc', 'accept', 'lockfile', 'stgisstoragefile', 'environ', 'messageboxa', 'getch', 'getprocessheap', 'getprivateprofilesectionw', 'pathfindextensiona', 'isrectempty', 'rtlunwind', 'replacefilew', 'regopenkeya', 'closesocket', 'loadregtypelib', 'setclassword', 'duplicatehandle', 'llseek', 'couninitialize', 'loadacceleratorsa', 'isdbcsleadbyte', 'globalflags', 'findresourceexa', 'strcmpi', 'getsysteminfo', 'createsemaphorew', 'writefile', 'gettimeformatw', 'imagelistdragmove', 'setmailslotinfo', 'issystemresumeautomatic', 'wsalookupservicenextw', 'setconsolewindowinfo', 'fillrect', 'certfreecertificatecontext', 'getdlgctrlid', 'interlockedincrement', 'getcurrentprocess', 'regcreatekeyexa', 'vbai2var', 'getdateformata', 'coinitialize', 'removedirectoryw', 'setsystemtimeadjustment', 'setunhandledexceptionfilter', 'winhttpquerydataavailable', 'dosdatetimetofiletime', 'variantchangetypeex', 'leavecriticalsection', 'setdibits', 'tlssetvalue', 'acmstreamreset', 'getprocaddress', 'globallock', 'getnumahighestnodenumber', 'fmode', 'adjustwindowrectex', 'pathremoveargsw', 'freeresource', 'scalewindowextex', 'createeventw', 'winhttpwritedata', 'wcsicmp', 'globalunlock', 'setbrushorgex', 'getprivateobjectsecurity', 'module32next', 'freelibrary', 'vbavarsub', 'createpatternbrush', 'gettimeformata', 'regqueryvalueexa', 'raiseexception', 'movefilewithprogressa', 'getconsoletitlea', 'netbios', 'comparestringa', 'vsnwprintf', 'getconsolealiaseslengtha', 'heapfree', 'sendmessagea', 'gettemppatha', 'setsystemtime', 'xcptfilter', 'initializeslisthead', 'cisqrt', 'getmodulehandlea', 'shellexecuteexw', 'writeprofilesectiona', 'movefilew', 'getcurrentprocessid', 'getace', 'gettickcount', 'getsystemmetrics', 'setlocaleinfoa', 'postquitmessage', 'copyimage', 'findatomw', 'setjmp3', 'variantcopy', 'lockresource', 'loadbitmapa', 'createmailslotw', 'onexit', 'getprivateprofilestructw', 'seterrormode', 'virtualallocexnuma', 'initializecriticalsectionex', 'getmainargs', 'interlockedpopentryslist', 'initterme', 'coutstd3vbasicostreamduchartraitsdstd1a', 'strstria', 'lcmapstringex', 'drawiconex', 'lock', 'pathfindfilenamea', 'setlocaltime', 'copyfileexw', 'vbai4str', 'rtlmovememory', 'getstdhandle', 'isbadwriteptr', 'interlockedflushslist', 'waitforsingleobject', 'pfmode', 'setendoffile', 'excepthandler4common', 'startservicectrldispatchera', 'choosecolorw', 'findnextfilea', 'coinitializesecurity', 'setfilepointerex', 'movefileexw', 'winhttpcreateurl', 'getmodulehandlew', 'abasicstringduchartraitsdstdvallocatord2stdqaeaadiz', 'virtualprotectex', 'releasesemaphore', 'getstartupinfoa', 'charlowerw', 'beep', 'virtualfree', 'getconsolecursorinfo', 'vbavar2vec', 'connectnamedpipe', 'vbaexcepthandler', 'getdevicepowerstate', 'settimerqueuetimer', 'free', 'unionrect', 'getdlgitemtexta', 'releasemutex', 'getconsolescreenbufferinfo', 'getwindowdc', 'getcurrentdirectoryw', 'cxxframehandler', 'getsystemtime', 'setdefaultcommconfigw', 'setcapture', 'openjobobjecta', 'kbdlayerdescriptor', 'terminateprocess', 'getvolumeinformationw', 'sizeofresource', 'enumsystemlocalesa', 'comparefiletime', 'getfileinformationbyhandle', 'getacp', 'regopenkeyw', 'localalloc', 'createfonta', 'deleteobject', 'controlfp', 'ntohl', 'enumsystemlocalesw', 'closedesktop', 'querydosdevicea', 'interlockedexchangeadd', 'setenvironmentvariablea', 'icmpsendecho', 'getversionexa', 'vsnprintf', 'createeventa', 'writeconsolew', 'getuserdefaultuilanguage', 'fillconsoleoutputcharacterw', 'startservicectrldispatcherw', 'enumchildwindows', 'gdipcreatebitmapfromstream', 'charupperbuffw', '0basicstringduchartraitsdstdvallocatord2stdqaexz', 'createdialogindirectparamw', 'movefileexa', 'convertdefaultlocale', 'gettextextentpointw', 'getvolumenameforvolumemountpointw', 'loadiconw', 'currentexceptioncontext', 'buildcommdcbandtimeoutsa', 'setfileapistoansi', 'vbastrmove', 'getsystemwindowsdirectoryw', 'getnumanodeprocessormask', 'shcreatedirectoryexw', 'reporteventw', 'lcmapstringa', 'safearrayunaccessdata', 'unhandledexceptionfilter', 'getbkcolor', 'peeknamedpipe', 'setsystempowerstate', 'srand', 'lookupaccountsidw', 'getnearestcolor', 'winhttpopen', 'addace', 'getmoduleinformation', 'getoutlinetextmetricsa', 'sehfilterexe', 'setthreadidealprocessor', 'winhttpsetoption', 'sysreallocstringlen', 'bringwindowtotop', 'waitformultipleobjects', 'strlen', 'isvalidcodepage', 'ptinrect', 'amsgexit', 'findvolumeclose', 'erasetape', 'getoemcp', 'invertrect', 'wtsgetactiveconsolesessionid', 'getcaretblinktime', 'regopenkeyexw', 'getlocaleinfoa', 'rand', 'isdbcsleadbyteex', 'loadstringa', 'setcalendarinfoa', 'freesid', 'cisin', 'callwindowprocw', 'wcsncpys', 'flushviewoffile', 'getcommtimeouts', 'ischild', 'getfileversioninfoa', 'httpaddrequestheadersw', 'rtllookupfunctionentry', 'getmodulehandleexw', 'getscrollinfo', 'copyicon', 'wsastartup', 'initializecriticalsectionandspincount', 'shgetdiskfreespacea', 'charprevw', 'getsavefilenamew', 'initatomtable', 'polygon', 'vyaxpaxz', 'backupwrite', 'hidecaret', 'thread32next', 'callnewh', 'debugbreakprocess', 'postthreadmessagew', 'enumthreadwindows', 'vbastrfixstr', 'regenumkeyw', 'pacmdln', 'oleuiaddverbmenua', 'getsystempaletteentries', 'oleuiobjectpropertiesa', 'vbaarylock', 'main', 'pathmakeuniquename', 'shgeticonoverlayindexa', 'timekillevent', 'fdidestroy', 'strcoll', 'loadcursorfromfilew', 'shgetdiskfreespaceexw', 'fontobjvgetinfo', 'xbadallocstdyaxxz', 'shchangenotifyregister', 'oleuieditlinksa', 'imagelistgeticon', 'isvalidsecuritydescriptor', 'checkmenuradioitem', 'enumfontfamiliesa', 'wcsftime', 'stdterminate', 'shstrdupw', 'backupseek', 'shellaboutw', 'wsaioctl', 'engfindresource', 'propertysheet', 'acmdriverdetailsa', 'getmodulebasenamea', 'wnetopenenumw', 'acquiresrwlockexclusive', 'wnetgetuniversalnamew', 'wtssendmessagew', 'loaduserprofilew', 'openinputdesktop']

    
    # 49 PE Header features (from document)
    PE_HEADER_FEATURES = ['MajorOperatingSystemVersion', 'e_minalloc', 'MajorImageVersion', 'e_ovno', 'e_lfanew', 'SizeOfHeaders', 'DllCharacteristics', 'SizeOfUninitializedData', 'SectionAlignment', 'MinorLinkerVersion', 'SizeOfHeapReserve', 'MinorSubsystemVersion', 'TimeDateStamp', 'SizeOfHeapCommit', 'e_oemid', 'Machine', 'Characteristics', 'e_cblp', 'BaseOfCode', 'e_cp', 'ImageBase', 'CheckSum', 'MajorLinkerVersion', 'SizeOfStackReserve', 'e_sp', 'e_ss', 'AddressOfEntryPoint', 'Subsystem', 'MinorOperatingSystemVersion', 'SizeOfInitializedData', 'SizeOfImage', 'e_cparhdr', 'SizeOfCode', 'FileAlignment', 'NumberOfRvaAndSizes', 'Reserved1', 'MajorSubsystemVersion', 'PointerToSymbolTable', 'e_lfarlc', 'e_crlc', 'NumberOfSections', 'MinorImageVersion', 'NumberOfSymbols', 'e_maxalloc', 'e_oeminfo', 'e_ip', 'e_cs', 'e_csum', 'Magic']
    
    # 48 PE Section features (from document)
    PE_SECTION_FEATURES = ['bss_PointerToRawData', 'rdata_Characteristics', 'reloc_SizeOfRawData', 'data_Misc_VirtualSize', 'tls_PointerToRawData', 'text_VirtualAddress', 'tls_Misc_VirtualSize', 'data_Characteristics', 'idata_Characteristics', 'data_PointerToRawData', 'data_VirtualAddress', 'data_SizeOfRawData', 'rsrc_Characteristics', 'reloc_Characteristics', 'text_SizeOfRawData', 'rdata_SizeOfRawData', 'rsrc_PointerToRawData', 'reloc_Misc_VirtualSize', 'rsrc_VirtualAddress', 'pdata_Misc_VirtualSize', 'text_Misc_VirtualSize', 'bss_VirtualAddress', 'text_PointerToRawData', 'text_PointerToLinenumbers', 'reloc_VirtualAddress', 'pdata_PointerToRawData', 'idata_Misc_VirtualSize', 'tls_VirtualAddress', 'reloc_PointerToRawData', 'rdata_VirtualAddress', 'rsrc_Misc_VirtualSize', 'rsrc_SizeOfRawData', 'rdata_Misc_VirtualSize', 'rdata_PointerToRawData', 'bss_Characteristics', 'tls_SizeOfRawData', 'idata_SizeOfRawData', 'text_Characteristics', 'pdata_VirtualAddress', 'idata_PointerToRawData', 'bss_Misc_VirtualSize', 'edata_PointerToRawData', 'idata_VirtualAddress', 'edata_VirtualAddress', 'pdata_SizeOfRawData', 'edata_Misc_VirtualSize', 'tls_NumberOfLinenumbers', 'bss_NumberOfRelocations']
    
    def __init__(self, model_features_path: Optional[Path] = None, expected_features: Optional[List[str]] = None):
        """Initialize the PE feature extractor with all 1000 features

        Args:
            model_features_path: optional path to a joblib file containing model feature list
            expected_features: optional explicit list of expected feature names
        """
        self.dll_list = self.DLL_LIST
        self.api_functions = self.API_FUNCTIONS
        self.pe_header_features = self.PE_HEADER_FEATURES
        self.pe_section_features = self.PE_SECTION_FEATURES

        # Load expected/model features if provided
        self.expected_features = None
        if model_features_path is not None:
            try:
                loaded = joblib.load(model_features_path)
                # joblib may return numpy array; convert to list
                if hasattr(loaded, 'tolist'):
                    loaded = list(loaded)
                self.expected_features = list(loaded)
            except Exception:
                # Fall back to provided expected_features or None
                self.expected_features = None

        if expected_features is not None:
            self.expected_features = list(expected_features)

        # Verify we have exactly 1000 features (internal configuration)
        total_features = (len(self.pe_header_features) + 
                         len(self.pe_section_features) + 
                         len(self.dll_list) + 
                         len(self.api_functions))
        print(f"Total features configured: {total_features}")
        assert total_features == 1000, f"Expected 1000 features, got {total_features}"
    
    def calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def extract_pe_headers(self, pe: pefile.PE) -> Dict:
        """Extract all PE header features (DOS + FILE + OPTIONAL)"""
        features = {}
        
        # DOS Header
        dos = pe.DOS_HEADER
        dos_features = {
            'e_cblp': dos.e_cblp,
            'e_cp': dos.e_cp,
            'e_crlc': dos.e_crlc,
            'e_cparhdr': dos.e_cparhdr,
            'e_minalloc': dos.e_minalloc,
            'e_maxalloc': dos.e_maxalloc,
            'e_ss': dos.e_ss,
            'e_sp': dos.e_sp,
            'e_csum': dos.e_csum,
            'e_ip': dos.e_ip,
            'e_cs': dos.e_cs,
            'e_lfarlc': dos.e_lfarlc,
            'e_ovno': dos.e_ovno,
            'e_oemid': dos.e_oemid,
            'e_oeminfo': dos.e_oeminfo,
            'e_lfanew': dos.e_lfanew
        }
        
        # FILE Header
        fh = pe.FILE_HEADER
        file_features = {
            'Machine': fh.Machine,
            'NumberOfSections': fh.NumberOfSections,
            'TimeDateStamp': fh.TimeDateStamp,
            'PointerToSymbolTable': fh.PointerToSymbolTable,
            'NumberOfSymbols': fh.NumberOfSymbols,
            'Characteristics': fh.Characteristics
        }
        
        # OPTIONAL Header
        oh = pe.OPTIONAL_HEADER
        optional_features = {
            'MajorLinkerVersion': oh.MajorLinkerVersion,
            'MinorLinkerVersion': oh.MinorLinkerVersion,
            'SizeOfCode': oh.SizeOfCode,
            'SizeOfInitializedData': oh.SizeOfInitializedData,
            'SizeOfUninitializedData': oh.SizeOfUninitializedData,
            'AddressOfEntryPoint': oh.AddressOfEntryPoint,
            'BaseOfCode': oh.BaseOfCode,
            'ImageBase': oh.ImageBase,
            'SectionAlignment': oh.SectionAlignment,
            'FileAlignment': oh.FileAlignment,
            'MajorOperatingSystemVersion': oh.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': oh.MinorOperatingSystemVersion,
            'MajorImageVersion': oh.MajorImageVersion,
            'MinorImageVersion': oh.MinorImageVersion,
            'MajorSubsystemVersion': oh.MajorSubsystemVersion,
            'MinorSubsystemVersion': oh.MinorSubsystemVersion,
            'Reserved1': getattr(oh, 'Reserved1', 0),
            'SizeOfImage': oh.SizeOfImage,
            'SizeOfHeaders': oh.SizeOfHeaders,
            'CheckSum': oh.CheckSum,
            'Subsystem': oh.Subsystem,
            'DllCharacteristics': oh.DllCharacteristics,
            'SizeOfStackReserve': oh.SizeOfStackReserve,
            'SizeOfHeapReserve': oh.SizeOfHeapReserve,
            'SizeOfHeapCommit': oh.SizeOfHeapCommit,
            'NumberOfRvaAndSizes': oh.NumberOfRvaAndSizes
        }
        
        features.update(dos_features)
        features.update(file_features)
        features.update(optional_features)
        
        # Initialize all header features to 0, then update with extracted values
        header_dict = {feat: 0 for feat in self.pe_header_features}
        header_dict.update(features)
        
        return header_dict
    
    def extract_sections(self, pe: pefile.PE) -> Dict:
        """Extract section features - only the 46 features from the list"""
        # Initialize all section features to 0
        features = {feat: 0 for feat in self.pe_section_features}
        
        # Parse sections and fill in values
        for section in pe.sections:
            try:
                name = section.Name.decode().strip('\x00').lower()
                
                # Map section name to prefix
                section_map = {
                    '.text': 'text',
                    '.data': 'data',
                    '.rdata': 'rdata',
                    '.bss': 'bss',
                    '.idata': 'idata',
                    '.edata': 'edata',
                    '.rsrc': 'rsrc',
                    '.reloc': 'reloc',
                    '.tls': 'tls',
                    '.pdata': 'pdata'
                }
                
                if name in section_map:
                    prefix = section_map[name]
                    
                    # Only extract the features that are in our PE_SECTION_FEATURES list
                    section_features = {
                        f'{prefix}_Misc_VirtualSize': section.Misc_VirtualSize,
                        f'{prefix}_VirtualAddress': section.VirtualAddress,
                        f'{prefix}_SizeOfRawData': section.SizeOfRawData,
                        f'{prefix}_PointerToRawData': section.PointerToRawData,
                        f'{prefix}_PointerToLinenumbers': section.PointerToLinenumbers,
                        f'{prefix}_Characteristics': section.Characteristics
                    }
                    
                    # Only update features that are in our list
                    for key, value in section_features.items():
                        if key in features:
                            features[key] = value
                            
            except Exception as e:
                continue
        
        return features
    
    def extract_imports(self, pe: pefile.PE) -> Dict:
        """Extract imported DLLs and API functions"""
        # Initialize all DLLs to 0
        dll_features = {dll: 0 for dll in self.dll_list}
        # Initialize all API functions to 0
        api_features = {func: 0 for func in self.api_functions}
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return {**dll_features, **api_features}
        
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower()
                
                # Mark DLL as imported
                if dll_name in dll_features:
                    dll_features[dll_name] = 1
                
                # Mark imported functions
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode().lower()
                        if func_name in api_features:
                            api_features[func_name] = 1
        except Exception as e:
            pass
        
        return {**dll_features, **api_features}
    
    def extract_features_from_file(self, file_path: Path, file_type: str = "unknown") -> Dict:
        """
        Extract all 1000 features from a PE file
        
        Args:
            file_path: Path to the PE file
            file_type: Optional malware type label
            
        Returns:
            Dictionary of all features
        """
        features = {}
        
        try:
            # Calculate SHA256
            features['SHA256'] = self.calculate_sha256(file_path)
            features['Type'] = file_type
            
            # Parse PE file
            pe = pefile.PE(str(file_path))
            
            # Extract all feature groups
            features.update(self.extract_pe_headers(pe))
            features.update(self.extract_sections(pe))
            features.update(self.extract_imports(pe))
            
            pe.close()
            
            # Verify we have exactly 1000 features + metadata
            feature_count = len(features) - 2  # Exclude SHA256 and Type
            if feature_count != 1000:
                print(f"Warning: Expected 1000 features, got {feature_count}")
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return None
        
        return features
    
    def extract_features_batch(self, file_paths: List[Path], 
                               labels: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Extract features from multiple PE files
        
        Args:
            file_paths: List of paths to PE files
            labels: Optional list of malware 00000000000type labels
            
        Returns:
            DataFrame with all 1000 features
        """
        if labels is None:
            labels = ["unknown"] * len(file_paths)
        
        all_features = []
        for file_path, label in zip(file_paths, labels):
            print(f"Processing: {file_path.name}")
            features = self.extract_features_from_file(file_path, label)
            if features:
                all_features.append(features)
        
        df = pd.DataFrame(all_features)
        
        # Reorder columns: SHA256, Type, then all 1000 features in specific order
        ordered_cols = (['SHA256', 'Type'] + 
                       self.pe_header_features + 
                       self.pe_section_features + 
                       self.dll_list + 
                       self.api_functions)
        
        # Ensure all columns exist
        for col in ordered_cols:
            if col not in df.columns:
                df[col] = 0
        
        df = df[ordered_cols]
        
        # Fill any remaining missing values with 0
        df = df.fillna(0)
        
        print(f"\nDataFrame shape: {df.shape}")
        print(f"Number of features (excluding SHA256, Type): {df.shape[1] - 2}")
        
        return df
    
    def prepare_for_prediction(self, df: pd.DataFrame, 
                              scaler_header, scaler_section,
                              expected_features: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Prepare extracted features for model prediction

        Args:
            df: DataFrame with extracted features
            scaler_header: Fitted StandardScaler for header features (48 features)
            scaler_section: Fitted StandardScaler for section features (46 features)
            expected_features: Optional list of feature names expected by the model
                                If not provided, uses the features loaded during init

        Returns:
            Processed DataFrame ready for prediction
        """
        df_processed = df.copy()

        # Scale header features (first 48 features after SHA256 and Type)
        header_cols = self.pe_header_features
        if all(col in df_processed.columns for col in header_cols):
            try:
                df_processed[header_cols] = scaler_header.transform(df_processed[header_cols])
            except Exception:
                # If scaler fails or not compatible, leave unscaled
                pass

        # Scale section features (next 46 features)
        section_cols = self.pe_section_features
        if all(col in df_processed.columns for col in section_cols):
            try:
                df_processed[section_cols] = scaler_section.transform(df_processed[section_cols])
            except Exception:
                pass

        # Ensure all expected/model features exist in DataFrame (fill missing with 0)
        features_to_check = expected_features or self.expected_features
        if features_to_check is not None:
            for col in features_to_check:
                if col not in df_processed.columns:
                    df_processed[col] = 0

        # No reordering here; caller may select/reorder columns as needed
        return df_processed


def main():
    """Example usage"""
    
    # Initialize extractor
    extractor = PEFeatureExtractor()
    
    # Example: Extract features from a single PE file
    pe_file = Path(r"C:\Windows\System32\notepad.exe")
    
    if pe_file.exists():
        print(f"Extracting features from: {pe_file}")
        features = extractor.extract_features_from_file(pe_file, file_type="unknown")
        
        if features:
            print(f"\nExtracted {len(features) - 2} features (excluding SHA256 and Type)")
            print(f"SHA256: {features['SHA256']}")
            
            # Show sample features from each category
            print("\nSample PE Header features:")
            for i, feat in enumerate(extractor.pe_header_features[:5]):
                print(f"  {feat}: {features.get(feat, 0)}")
            
            print("\nSample PE Section features:")
            for i, feat in enumerate(extractor.pe_section_features[:5]):
                print(f"  {feat}: {features.get(feat, 0)}")
            
            print("\nSample DLL features:")
            for i, dll in enumerate(extractor.dll_list[:5]):
                print(f"  {dll}: {features.get(dll, 0)}")
            
            print("\nSample API features:")
            for i, api in enumerate(extractor.api_functions[:5]):
                print(f"  {api}: {features.get(api, 0)}")
    else:
        print(f"File not found: {pe_file}")
    
    # Example: Batch extraction
    # pe_files = list(Path("path/to/pe/files").glob("*.exe"))
    # if pe_files:
    #     print(f"\nProcessing {len(pe_files)} PE files...")
    #     df = extractor.extract_features_batch(pe_files)
    #     print(f"\nExtracted features shape: {df.shape}")
    #     
    #     # Save to CSV
    #     output_path = Path('extracted_pe_features_1000.csv')
    #     df.to_csv(output_path, index=False)
    #     print(f"Features saved to: {output_path}")


if __name__ == "__main__":
    main()