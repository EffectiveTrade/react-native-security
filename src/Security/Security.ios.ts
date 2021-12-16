import { NativeModules } from 'react-native';

const NativeAuth = NativeModules.VBNativeAuth;

interface INativeError {
  code: number | string;
  message?: string;
  subCode?: string;
}

function correctError(error: INativeError) {
  error.code = parseInt(`${error.code}`, 10);
  // ✅ error.subCode - необходимости заполнять не было
  return error;
}

export default {
  clean() {
    return new Promise((resolve, reject) => {
      NativeAuth.clean((error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve({ code: 0 });
        }
      });
    });
  },

  saveCred(login: string, password: string, code: string) {
    return new Promise((resolve, reject) => {
      NativeAuth.saveCred(login, password, code, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve({ code: 0 });
        }
      });
    });
  },

  unlockByCode(code: string) {
    return new Promise((resolve, reject) => {
      NativeAuth.unlockByCode(code, (error: INativeError, login: string, password: string) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve({ code: 0, login, password });
        }
      });
    });
  },

  saveCredByBiometry(login: string, password: string) {
    const rv = new Promise((resolve, reject) => {
      NativeAuth.saveCredByBiometry(login, password, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve({ code: 0 });
        }
      });
    });

    (rv as any).cancel = () => {
      /*not supported: iOS unlock by biometry dialog is modal*/
    };

    return rv;
  },

  isSupported() {
    //TODO
  },

  unlockByBiometry(text: string) {
    const rv = new Promise((resolve, reject) => {
      NativeAuth.unlockByBiometry(text, (error: INativeError, login: string, password: string) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve({ code: 0, login, password });
        }
      });
    });

    (rv as any).cancel = () => {
      /*not supported: iOS unlock by biometry dialog is modal*/
    };

    return rv;
  },
};
