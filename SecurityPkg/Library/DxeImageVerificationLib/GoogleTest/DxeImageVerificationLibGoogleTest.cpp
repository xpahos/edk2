/** @file
  Unit tests for the implementation of DxeImageVerificationLib.

  Copyright (c) 2025, Yandex
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockUefiLib.h>
#include <GoogleTest/Library/MockUefiRuntimeServicesTableLib.h>
#include <GoogleTest/Library/MockUefiBootServicesTableLib.h>
#include <GoogleTest/Library/MockDevicePathLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/DebugLib.h>

  #include "DxeImageVerificationLibGoogleTest.h"
  #include "../DxeImageVerificationLib.h"
}

//////////////////////////////////////////////////////////////////////////////
void
RoutinesBeforeHashCheck (
  MockUefiBootServicesTableLib     &BsMock,
  MockDevicePathLib                &DevicePathMock,
  MockUefiRuntimeServicesTableLib  &RtServicesMock
  )
{
  UINT8  SetupMode = SECURE_BOOT_MODE_ENABLE;

  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .Times (3)
    .WillRepeatedly (testing::Return (EFI_NOT_FOUND));
  EXPECT_CALL (DevicePathMock, IsDevicePathEndType)
    .WillOnce (testing::Return ((BOOLEAN)TRUE));

  EXPECT_CALL (
    RtServicesMock,
    gRT_GetVariable (
      Char16StrEq (EFI_SECURE_BOOT_MODE_NAME),
      BufferEq (&gEfiGlobalVariableGuid, sizeof (EFI_GUID)),
      testing::NotNull (),
      testing::Pointee (testing::Eq (sizeof (SetupMode))),
      testing::NotNull ()
      )
    ).WillOnce (
        testing::DoAll (
                   testing::SetArgPointee<3>(sizeof (SetupMode)),
                   SetArgBuffer<4>(&SetupMode, sizeof (SetupMode)),
                   testing::Return (EFI_SUCCESS)
                   )
        );
}

void
SkipHashChecks (
  MockUefiRuntimeServicesTableLib  &RtServicesMock,
  int                              n
  )
{
  // Here, the cycle and WillOnce are used because InSequence must be specified
  // in the main function. When using InSequence, Times will retire.
  for (int i = 0; i < n; i++) {
    // Return ‘not found’ for DBx to exit from the first IsSignatureFoundInDatabase
    EXPECT_CALL (
      RtServicesMock,
      gRT_GetVariable (
        Char16StrEq (EFI_IMAGE_SECURITY_DATABASE1),
        BufferEq (&gEfiImageSecurityDatabaseGuid, sizeof (EFI_GUID)),
        testing::IsNull (),
        testing::Pointee (testing::Eq ((UINTN)0)),
        testing::IsNull ()
        )
      ).WillOnce (testing::Return (EFI_NOT_FOUND));

    // IsFound is false, EFI_NOT_FOUND will proceed to the next algorithm
    EXPECT_CALL (
      RtServicesMock,
      gRT_GetVariable (
        Char16StrEq (EFI_IMAGE_SECURITY_DATABASE),
        BufferEq (&gEfiImageSecurityDatabaseGuid, sizeof (EFI_GUID)),
        testing::IsNull (),
        testing::Pointee (testing::Eq ((UINTN)0)),
        testing::IsNull ()
        )
      ).WillOnce (testing::Return (EFI_NOT_FOUND));
  }
}

template<size_t N>
void
SetHashDBValue (
  MockUefiRuntimeServicesTableLib  &RtServicesMock,
  UINT8                            (&CertListBuffer)[N],
  UINTN                            BufferSize
  )
{
  // Return ‘not found’ for DBx to exit from the first IsSignatureFoundInDatabase
  EXPECT_CALL (
    RtServicesMock,
    gRT_GetVariable (
      Char16StrEq (EFI_IMAGE_SECURITY_DATABASE1),
      BufferEq (&gEfiImageSecurityDatabaseGuid, sizeof (EFI_GUID)),
      testing::IsNull (),
      testing::Pointee (testing::Eq ((UINTN)0)),
      testing::IsNull ()
      )
    ).WillOnce (testing::Return (EFI_NOT_FOUND));

  // Second call of IsSignatureFoundInDatabase for DB
  // Get Size
  EXPECT_CALL (
    RtServicesMock,
    gRT_GetVariable (
      Char16StrEq (EFI_IMAGE_SECURITY_DATABASE),
      BufferEq (&gEfiImageSecurityDatabaseGuid, sizeof (EFI_GUID)),
      testing::IsNull (),
      testing::Pointee (testing::Eq ((UINTN)0)),
      testing::IsNull ()
      )
    ).WillOnce (
        testing::DoAll (
                   testing::SetArgPointee<3>(BufferSize),
                   testing::Return (EFI_BUFFER_TOO_SMALL)
                   )
        );

  // Return hash
  EXPECT_CALL (
    RtServicesMock,
    gRT_GetVariable (
      Char16StrEq (EFI_IMAGE_SECURITY_DATABASE),
      BufferEq (&gEfiImageSecurityDatabaseGuid, sizeof (EFI_GUID)),
      testing::IsNull (),
      testing::Pointee (testing::Eq ((UINTN)BufferSize)),
      testing::NotNull ()
      )
    ).WillOnce (
        testing::DoAll (
                   testing::SetArgPointee<3>(BufferSize),
                   SetArgBuffer<4>(&CertListBuffer[0], BufferSize),
                   testing::Return (EFI_SUCCESS)
                   )
        );

  // Hash verification does't exit the loop upon the first match
  EXPECT_CALL (RtServicesMock, gRT_GetVariable)
    .Times (testing::AnyNumber ())
    .WillRepeatedly (testing::Return (EFI_NOT_FOUND));
}

void
HandleFailureJump (
  MockDevicePathLib             &DevicePathMock,
  MockUefiLib                   &UefiMock,
  MockUefiBootServicesTableLib  &BsMock
  )
{
  EXPECT_CALL (DevicePathMock, ConvertDevicePathToText)
    .WillOnce (testing::Return (NULL));

  EXPECT_CALL (UefiMock, EfiGetSystemConfigurationTable)
    .WillOnce (testing::Return (EFI_NOT_FOUND));

  EXPECT_CALL (DevicePathMock, GetDevicePathSize)
    .WillOnce (testing::Return ((UINTN)0));

  EXPECT_CALL (BsMock, gBS_InstallConfigurationTable)
    .WillOnce (testing::Return (EFI_SUCCESS));
}

//////////////////////////////////////////////////////////////////////////////
class CheckImageTypeResult : public ::testing::Test {
public:
  EFI_DEVICE_PATH_PROTOCOL File;

protected:
  MockUefiRuntimeServicesTableLib RtServicesMock;
  MockUefiBootServicesTableLib BsMock;
  MockDevicePathLib DevicePathMock;

  EFI_STATUS Status;

  UINT32 AuthenticationStatus;
  VOID *FileBuffer;
  UINTN FileSize;
  BOOLEAN BootPolicy;

  virtual void
  SetUp (
    )
  {
    AuthenticationStatus = 0;
    FileBuffer           = NULL;
    FileSize             = 0;
    BootPolicy           = FALSE;
  }
};

TEST_F (CheckImageTypeResult, ImageTypeVerifySanity) {
  // Sanity check
  Status = DxeImageVerificationHandler (AuthenticationStatus, NULL, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_INVALID_PARAMETER);
}

TEST_F (CheckImageTypeResult, ImageTypeVerifyImageFromFv) {
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillRepeatedly (testing::Return (EFI_SUCCESS));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillRepeatedly (testing::Return (EFI_SUCCESS));

  Status = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_SUCCESS);
}

TEST_F (CheckImageTypeResult, ImageTypeVerifyImageFromOptionRom) {
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .Times (3)
    .WillRepeatedly (testing::Return (EFI_NOT_FOUND));
  EXPECT_CALL (BsMock, gBS_OpenProtocol)
    .WillRepeatedly (testing::Return (EFI_NOT_FOUND));
  EXPECT_CALL (DevicePathMock, IsDevicePathEndType)
    .WillOnce (testing::Return ((BOOLEAN)FALSE));
  EXPECT_CALL (DevicePathMock, DevicePathType)
    .WillOnce (testing::Return ((UINT8)MEDIA_DEVICE_PATH));
  EXPECT_CALL (DevicePathMock, DevicePathSubType)
    .WillOnce (testing::Return ((UINT8)MEDIA_RELATIVE_OFFSET_RANGE_DP));

  Status = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_ACCESS_DENIED);
}

TEST_F (CheckImageTypeResult, ImageTypeVerifyImageFromRemovableMedia) {
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .Times (3)
    .WillRepeatedly (testing::Return (EFI_NOT_FOUND));
  EXPECT_CALL (DevicePathMock, IsDevicePathEndType)
    .WillOnce (testing::Return ((BOOLEAN)FALSE));
  EXPECT_CALL (DevicePathMock, DevicePathType)
    .WillOnce (testing::Return ((UINT8)MESSAGING_DEVICE_PATH));
  EXPECT_CALL (DevicePathMock, DevicePathSubType)
    .WillOnce (testing::Return ((UINT8)MSG_MAC_ADDR_DP));

  Status = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_ACCESS_DENIED);
}

TEST_F (CheckImageTypeResult, ImageTypeVerifyImageFromFixedMedia) {
  EXPECT_CALL (BsMock, gBS_LocateDevicePath)
    .WillOnce (testing::Return (EFI_NOT_FOUND))
    .WillOnce (testing::Return (EFI_NOT_FOUND))
    .WillOnce (testing::Return (EFI_SUCCESS));

  Status = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_ACCESS_DENIED);
}

//////////////////////////////////////////////////////////////////////////////
class CheckUnsignedImage : public ::testing::Test {
public:
  EFI_DEVICE_PATH_PROTOCOL File;

protected:
  MockUefiRuntimeServicesTableLib RtServicesMock;
  MockUefiBootServicesTableLib BsMock;
  MockDevicePathLib DevicePathMock;
  MockUefiLib UefiMock;

  EFI_STATUS Status;

  UINT32 AuthenticationStatus;
  VOID *FileBuffer;
  UINTN FileSize;
  BOOLEAN BootPolicy;

  virtual void
  SetUp (
    )
  {
    AuthenticationStatus = 0;
    FileBuffer           = NULL;
    FileSize             = 0;
    BootPolicy           = FALSE;
  }
};

TEST_F (CheckUnsignedImage, HashNormalFlowSha512) {
  constexpr UINTN  Size       = sizeof (images::UnsignedCOFFSha512);
  constexpr UINTN  BufferSize = sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA) - 1 + Size;

  UINT8  CertListBuffer[BufferSize] = { 0 };

  EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)CertListBuffer;

  CertList->SignatureListSize   = (UINT32)BufferSize;
  CertList->SignatureSize       = (UINT32)(sizeof (EFI_SIGNATURE_DATA) - 1 + Size);
  CertList->SignatureHeaderSize = 0;
  CopyGuid (&CertList->SignatureType, &gEfiCertSha512Guid);

  EFI_SIGNATURE_DATA  *Data = (EFI_SIGNATURE_DATA *)(CertList + 1);

  CopyGuid (&Data->SignatureOwner, &gEfiGlobalVariableGuid);
  CopyMem (&Data->SignatureData[0], &images::UnsignedCOFFSha512, Size);

  // Do not delete this. Otherwise, GetVariable from SetHashDBValue will match all calls.
  testing::InSequence  s;

  RoutinesBeforeHashCheck (BsMock, DevicePathMock, RtServicesMock);

  SetHashDBValue<BufferSize> (RtServicesMock, CertListBuffer, BufferSize);

  FileBuffer = (VOID *)&images::UnsignedCOFF;
  FileSize   = sizeof (images::UnsignedCOFF);
  Status     = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_SUCCESS);
}

TEST_F (CheckUnsignedImage, HashNormalFlowSha384) {
  constexpr UINTN  Size       = sizeof (images::UnsignedCOFFSha384);
  constexpr UINTN  BufferSize = sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA) - 1 + Size;

  UINT8  CertListBuffer[BufferSize] = { 0 };

  EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)CertListBuffer;

  CertList->SignatureListSize   = (UINT32)BufferSize;
  CertList->SignatureSize       = (UINT32)(sizeof (EFI_SIGNATURE_DATA) - 1 + Size);
  CertList->SignatureHeaderSize = 0;
  CopyGuid (&CertList->SignatureType, &gEfiCertSha384Guid);

  EFI_SIGNATURE_DATA  *Data = (EFI_SIGNATURE_DATA *)(CertList + 1);

  CopyGuid (&Data->SignatureOwner, &gEfiGlobalVariableGuid);
  CopyMem (&Data->SignatureData[0], &images::UnsignedCOFFSha384, Size);

  // Do not delete this. Otherwise, GetVariable from SetHashDBValue will match all calls.
  testing::InSequence  s;

  RoutinesBeforeHashCheck (BsMock, DevicePathMock, RtServicesMock);

  // Skip SHA512 check
  SkipHashChecks (RtServicesMock, 1);

  // SHA384 check
  SetHashDBValue<BufferSize> (RtServicesMock, CertListBuffer, BufferSize);

  FileBuffer = (VOID *)&images::UnsignedCOFF;
  FileSize   = sizeof (images::UnsignedCOFF);
  Status     = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_SUCCESS);
}

TEST_F (CheckUnsignedImage, HashNormalFlowSha256) {
  constexpr UINTN  Size       = sizeof (images::UnsignedCOFFSha256);
  constexpr UINTN  BufferSize = sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA) - 1 + Size;

  UINT8  CertListBuffer[BufferSize] = { 0 };

  EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)CertListBuffer;

  CertList->SignatureListSize   = (UINT32)BufferSize;
  CertList->SignatureSize       = (UINT32)(sizeof (EFI_SIGNATURE_DATA) - 1 + Size);
  CertList->SignatureHeaderSize = 0;
  CopyGuid (&CertList->SignatureType, &gEfiCertSha256Guid);

  EFI_SIGNATURE_DATA  *Data = (EFI_SIGNATURE_DATA *)(CertList + 1);

  CopyGuid (&Data->SignatureOwner, &gEfiGlobalVariableGuid);
  CopyMem (&Data->SignatureData[0], &images::UnsignedCOFFSha256, Size);

  // Do not delete this. Otherwise, GetVariable from SetHashDBValue will match all calls.
  testing::InSequence  s;

  RoutinesBeforeHashCheck (BsMock, DevicePathMock, RtServicesMock);

  // Skip SHA512, SHA384 check
  SkipHashChecks (RtServicesMock, 2);

  // SHA256 check
  SetHashDBValue<BufferSize> (RtServicesMock, CertListBuffer, BufferSize);

  FileBuffer = (VOID *)&images::UnsignedCOFF;
  FileSize   = sizeof (images::UnsignedCOFF);
  Status     = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_SUCCESS);
}

TEST_F (CheckUnsignedImage, HashNormalFlowSha1) {
  constexpr UINTN  Size       = sizeof (images::UnsignedCOFFSha1);
  constexpr UINTN  BufferSize = sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA) - 1 + Size;

  UINT8  CertListBuffer[BufferSize] = { 0 };

  EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)CertListBuffer;

  CertList->SignatureListSize   = (UINT32)BufferSize;
  CertList->SignatureSize       = (UINT32)(sizeof (EFI_SIGNATURE_DATA) - 1 + Size);
  CertList->SignatureHeaderSize = 0;
  CopyGuid (&CertList->SignatureType, &gEfiCertSha1Guid);

  EFI_SIGNATURE_DATA  *Data = (EFI_SIGNATURE_DATA *)(CertList + 1);

  CopyGuid (&Data->SignatureOwner, &gEfiGlobalVariableGuid);
  CopyMem (&Data->SignatureData[0], &images::UnsignedCOFFSha1, Size);

  // Do not delete this. Otherwise, GetVariable from SetHashDBValue will match all calls.
  testing::InSequence  s;

  RoutinesBeforeHashCheck (BsMock, DevicePathMock, RtServicesMock);

  // Skip SHA512, SHA384, SHA256 check
  SkipHashChecks (RtServicesMock, 3);

  SetHashDBValue<BufferSize> (RtServicesMock, CertListBuffer, BufferSize);

  // Last check. No need to loop.
  FileBuffer = (VOID *)&images::UnsignedCOFF;
  FileSize   = sizeof (images::UnsignedCOFF);
  Status     = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_SUCCESS);
}

TEST_F (CheckUnsignedImage, HashNoDBRecods) {
  // Do not delete this. Otherwise, GetVariable from SetHashDBValue will match all calls.
  testing::InSequence  s;

  RoutinesBeforeHashCheck (BsMock, DevicePathMock, RtServicesMock);

  // Skip SHA512, SHA384, SHA256, SHA1 check
  SkipHashChecks (RtServicesMock, 4);

  HandleFailureJump (DevicePathMock, UefiMock, BsMock);

  // Last check. No need to loop.
  FileBuffer = (VOID *)&images::UnsignedCOFF;
  FileSize   = sizeof (images::UnsignedCOFF);
  Status     = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_ACCESS_DENIED);
}

TEST_F (CheckUnsignedImage, HashFoundDBx) {
  constexpr UINTN  Size       = sizeof (images::UnsignedCOFFSha512);
  constexpr UINTN  BufferSize = sizeof (EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA) - 1 + Size;

  UINT8  CertListBuffer[BufferSize] = { 0 };

  EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)CertListBuffer;

  CertList->SignatureListSize   = (UINT32)BufferSize;
  CertList->SignatureSize       = (UINT32)(sizeof (EFI_SIGNATURE_DATA) - 1 + Size);
  CertList->SignatureHeaderSize = 0;
  CopyGuid (&CertList->SignatureType, &gEfiCertSha512Guid);

  EFI_SIGNATURE_DATA  *Data = (EFI_SIGNATURE_DATA *)(CertList + 1);

  CopyGuid (&Data->SignatureOwner, &gEfiGlobalVariableGuid);
  CopyMem (&Data->SignatureData[0], &images::UnsignedCOFFSha512, Size);

  // Do not delete this. Otherwise, GetVariable from SetHashDBValue will match all calls.
  testing::InSequence  s;

  RoutinesBeforeHashCheck (BsMock, DevicePathMock, RtServicesMock);

  // DBx routines
  EXPECT_CALL (
    RtServicesMock,
    gRT_GetVariable (
      Char16StrEq (EFI_IMAGE_SECURITY_DATABASE1),
      BufferEq (&gEfiImageSecurityDatabaseGuid, sizeof (EFI_GUID)),
      testing::IsNull (),
      testing::Pointee (testing::Eq ((UINTN)0)),
      testing::IsNull ()
      )
    ).WillOnce (
        testing::DoAll (
                   testing::SetArgPointee<3>(BufferSize),
                   testing::Return (EFI_BUFFER_TOO_SMALL)
                   )
        );

  // Return hash
  EXPECT_CALL (
    RtServicesMock,
    gRT_GetVariable (
      Char16StrEq (EFI_IMAGE_SECURITY_DATABASE1),
      BufferEq (&gEfiImageSecurityDatabaseGuid, sizeof (EFI_GUID)),
      testing::IsNull (),
      testing::Pointee (testing::Eq ((UINTN)BufferSize)),
      testing::NotNull ()
      )
    ).WillOnce (
        testing::DoAll (
                   testing::SetArgPointee<3>(BufferSize),
                   SetArgBuffer<4>(&CertListBuffer[0], BufferSize),
                   testing::Return (EFI_SUCCESS)
                   )
        );

  HandleFailureJump (DevicePathMock, UefiMock, BsMock);

  // Last check. No need to loop.
  FileBuffer = (VOID *)&images::UnsignedCOFF;
  FileSize   = sizeof (images::UnsignedCOFF);
  Status     = DxeImageVerificationHandler (AuthenticationStatus, &File, FileBuffer, FileSize, BootPolicy);
  EXPECT_EQ (Status, EFI_ACCESS_DENIED);
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}
