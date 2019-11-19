%module cfdgo
%{
#include "external/cfd/include/cfdc/cfdcapi_common.h"
%}

%insert(cgo_comment_typedefs) %{
#cgo LDFLAGS: -L/usr/local/lib -L${SRCDIR}/build/Release -L${SRCDIR}/build/Debug -lcfd
%}

%include "external/cfd/include/cfdc/cfdcapi_common.h"

