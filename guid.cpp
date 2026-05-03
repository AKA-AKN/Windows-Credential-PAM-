//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#include <initguid.h>
#include "guid.h"
#include <windows.h> // Ensure EXTERN_C is defined
#define INITGUID
// The Provider GUID (Matching your Register.reg)
// {5fd3d285-0dd9-4362-8855-e0abaacd4af6}
DEFINE_GUID(CLSID_CSample, 0x5fd3d285, 0x0dd9, 0x4362, 0x88, 0x55, 0xe0, 0xab, 0xaa, 0xcd, 0x4a, 0xf6);

// The Filter GUID (The Bouncer)
// {B0B47A83-05B3-4E83-9C1C-A1AE6632B9EE}
DEFINE_GUID(CLSID_CFilter, 0xB0B47A83, 0x05B3, 0x4E83, 0x9C, 0x1C, 0xA1, 0xAE, 0x66, 0x32, 0xB9, 0xEE);