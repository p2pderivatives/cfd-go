%module cfdgo
%{
#include "cfdc/cfdcapi_common.h"
#include "cfdc/cfdcapi_address.h"
#include "cfdc/cfdcapi_block.h"
#include "cfdc/cfdcapi_coin.h"
#include "cfdc/cfdcapi_elements_address.h"
#include "cfdc/cfdcapi_elements_transaction.h"
#include "cfdc/cfdcapi_key.h"
#include "cfdc/cfdcapi_ledger.h"
#include "cfdc/cfdcapi_script.h"
#include "cfdc/cfdcapi_transaction.h"
%}

%typemap(argout) (char **) {
  if ($1 && *$1) {
    $input->n = strlen(*$1);
  }
}

%insert(cgo_comment_typedefs) %{
#cgo CXXFLAGS: -I./external/cfd/include -I/usr/local/include -I/c/usr/local/include -IC:/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -L/usr/local/lib64 -L/c/usr/local/lib -LC:/usr/local/lib -L${SRCDIR}/build/Release -L${SRCDIR}/build/Debug -lcfd -lcfdcore -lunivalue -lwally
%}

%include "external/cfd/include/cfdc/cfdcapi_common.h"
%include "external/cfd/include/cfdc/cfdcapi_address.h"
%include "external/cfd/include/cfdc/cfdcapi_block.h"
%include "external/cfd/include/cfdc/cfdcapi_coin.h"
%include "external/cfd/include/cfdc/cfdcapi_elements_address.h"
%include "external/cfd/include/cfdc/cfdcapi_elements_transaction.h"
%include "external/cfd/include/cfdc/cfdcapi_key.h"
%include "external/cfd/include/cfdc/cfdcapi_ledger.h"
%include "external/cfd/include/cfdc/cfdcapi_script.h"
%include "external/cfd/include/cfdc/cfdcapi_transaction.h"
