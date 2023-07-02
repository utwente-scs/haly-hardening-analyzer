from detectors.detector import Detector
from androguard.core.bytecodes import apk
from models.message import DynamicMessage
from models.nativebinary import NativeBinary
from inc.context import Context
import plistlib

class InfoDetector(Detector):
    def __init__(self):
        super().__init__()
        self.static_results = {}

    def get_id(self) -> str:
        return 'info'

    def static_analyze_manifest(self, app_apk: apk.APK):
        self.static_results['name'] = app_apk.get_app_name()
        self.static_results['package'] = app_apk.get_package()
        self.static_results['version_code'] = int(app_apk.get_androidversion_code())
        self.static_results['version_name'] = app_apk.get_androidversion_name()
        self.static_results['min_sdk'] = app_apk.get_min_sdk_version()
        
        self.static_results['main_activity'] = app_apk.get_main_activity()
        
        self.static_results['permissions'] = list(set(app_apk.get_permissions()))

    def static_analyze_info_plist(self, plist: dict):
        self.static_results['name'] = plist['CFBundleDisplayName'] if 'CFBundleDisplayName' in plist else plist['CFBundleName']
        self.static_results['package'] = plist['CFBundleIdentifier']
        self.static_results['executable'] = plist['CFBundleExecutable']
        self.static_results['version_code'] = plist['CFBundleVersion']
        self.static_results['version_name'] = plist['CFBundleShortVersionString']
        self.static_results['min_sdk'] = plist['MinimumOSVersion'] if 'MinimumOSVersion' in plist else None

        self.static_results['main_activity'] = plist['UILaunchStoryboardName'] if 'UILaunchStoryboardName' in plist else None

        ios_permissions = ['NSBluetoothAlwaysUsageDescription', 'NSBluetoothPeripheralUsageDescription', 'NSCalendarsUsageDescription', 'NSRemindersUsageDescription', 'NSCameraUsageDescription', 'NSMicrophoneUsageDescription', 'NSContactsUsageDescription', 'NSFaceIDUsageDescription', 'NSDesktopFolderUsageDescription', 'NSDocumentsFolderUsageDescription', 'NSDownloadsFolderUsageDescription', 'NSNetworkVolumesUsageDescription', 'NSRemovableVolumesUsageDescription', 'NSFileProviderDomainUsageDescription', 'NSGKFriendListUsageDescription', 'NSHealthClinicalHealthRecordsShareUsageDescription', 'NSHealthShareUsageDescription', 'NSHealthUpdateUsageDescription', 'NSHealthRequiredReadAuthorizationTypeIdentifiers', 'NSHomeKitUsageDescription', 'NSLocationAlwaysAndWhenInUseUsageDescription', 'NSLocationUsageDescription', 'NSLocationWhenInUseUsageDescription', 'NSLocationTemporaryUsageDescriptionDictionary', 'NSLocationAlwaysUsageDescription', 'NSWidgetWantsLocation', 'NSLocationDefaultAccuracyReduced', 'NSAppleMusicUsageDescription', 'NSMotionUsageDescription', 'NSFallDetectionUsageDescription', 'NSLocalNetworkUsageDescription', 'NSNearbyInteractionUsageDescription', 'NSNearbyInteractionAllowOnceUsageDescription', 'NFCReaderUsageDescription', 'NSPhotoLibraryAddUsageDescription', 'NSPhotoLibraryUsageDescription', 'NSAppleScriptEnabled', 'NSUpdateSecurityPolicy', 'NSUserTrackingUsageDescription', 'NSAppleEventsUsageDescription', 'NSSystemAdministrationUsageDescription', 'ITSAppUsesNonExemptEncryption', 'ITSEncryptionExportComplianceCode', 'NSSensorKitUsageDescription', 'NSSensorKitUsageDetail', 'NSSensorKitPrivacyPolicyURL', 'NSSiriUsageDescription', 'NSSpeechRecognitionUsageDescription', 'NSVideoSubscriberAccountUsageDescription', 'NSIdentityUsageDescription', 'UIRequiresPersistentWiFi']
        self.static_results['permissions'] = {permission: plist[permission] for permission in ios_permissions if permission in plist}

    def static_analyze_r2(self, binary: NativeBinary) -> None:
        if Context().is_ios():
            info = binary.exec_r2_cmd('iCj')
            if info is not None:
                entitlements = info['signature'] if 'signature' in info else None
                self.static_results['entitlements'] = plistlib.loads(entitlements.encode('utf-8')) if entitlements else None

    def dynamic_get_data(self) -> dict:
        return {
            'info': {
                'package': self.static_results['package'] if 'package' in self.static_results else Context().app.package_id,
                'executable': self.static_results['executable'] if 'executable' in self.static_results else None,
            }
        }

    def dynamic_handle_message(self, message: DynamicMessage) -> bool:
        if message.detector != 'info':
            return False

        self.dynamic_results = message.info

        return True