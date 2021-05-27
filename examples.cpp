// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main() {
  cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
  while (true) {
    cout << "+---------------------------------------------------------+" << endl;
    cout << "| The following examples should be executed while reading |" << endl;
    cout << "| comments in associated files in native/examples/.       |" << endl;
    cout << "+---------------------------------------------------------+" << endl;
    cout << "| Examples                   | Source Files               |" << endl;
    cout << "+----------------------------+----------------------------+" << endl;
    cout << "| 1. Module 1                | ckks_basics.cpp            |" << endl;
    cout << "| 2. Module 2                | ckks_advanced.cpp          |" << endl;
    cout << "+----------------------------+----------------------------+" << endl;

    /*
    Print how much memory we have allocated from the current memory pool.
    By default the memory pool will be a static global pool and the
    MemoryManager class can be used to change it. Most users should have
    little or no reason to touch the memory allocation system.
    */
    size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
    cout << "[" << setw(7) << right << megabytes << " MB] "
         << "Total allocation from the memory pool" << endl;

    int selection = 0;
    bool valid = true;
    do {
      cout << endl << "> Run example (1) or exit (0): ";
      if (!(cin >> selection)) {
        valid = false;
      } else if (selection < 0 || selection > 2) {
        valid = false;
      } else {
        valid = true;
      }
      if (!valid) {
        cout << "  [Beep~~] valid option: type 0 ~ 2" << endl;
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
      }
    } while (!valid);

    switch (selection) {
      case 1:ckks_module1();
        break;

      case 2:ckks_module2();
        break;

      case 0:return 0;
    }
  }

  return 0;
}
