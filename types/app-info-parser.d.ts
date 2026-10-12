declare module "app-info-parser" {
  interface ApkParserResult {
    package?: string;
    versionName?: string;
    versionCode?: string | number;
    usesPermission?: string[];
    application?: {
      label?: string;
      icon?: string;
      activity?: Array<{ name: string }>;
      [key: string]: any;
    };
    [key: string]: any;
  }

  class ApkParser {
    constructor(file: Buffer | ArrayBuffer | Uint8Array | string);
    parse(): Promise<ApkParserResult>;
  }

  export default ApkParser;
}