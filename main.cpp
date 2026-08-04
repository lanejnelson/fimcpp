#include <iostream>
#include <stdlib.h>
#include <wintoastlib.h>
#include <vector>
#include <string>
#include <fstream>
#include <botan/hash.h>
#include <botan/hex.h>
#include <algorithm>


using namespace std;
using namespace WinToastLib;


class WinToastHandlerExample : public IWinToastHandler {
public:
	WinToastHandlerExample() {
		//cout << "Constructor" << endl;
	}
	// Public interfaces
	void toastActivated() const override {
		cout << "Activated" << endl;
	}
	void toastActivated(wstring response) const override {
		cout << "Activated" << endl;
	}
	void toastActivated(int actionIndex) const override {
		cout << "Activated" << endl;
	}
	void toastDismissed(WinToastDismissalReason state) const override {
		cout << "Dismissed" << endl;
	}
	void toastFailed() const override {
		cout << "Failed" << endl;
	}
};

std::wstring ConvertUtf8ToWide(const std::string& str)
{
	int count = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), NULL, 0);
	std::wstring wstr(count, 0);
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), &wstr[0], count);
	return wstr;
}

void popNotification(const string filePath) {
	WinToast::instance()->setAppName(L"file-integrity-monitor");
	const auto aumi = WinToast::configureAUMI(L"lane", L"notification", L"fileintegritymonitor", L"20260721");
	WinToast::instance()->setAppUserModelId(aumi);
	WinToastTemplate templ = WinToastTemplate(WinToastTemplate::Text02);
	templ.setTextField(L"File Contents Modification Detected", WinToastTemplate::FirstLine);
	wstring wideFilePath = ConvertUtf8ToWide(filePath);
	templ.setTextField(L"Modification detected on file " + wideFilePath, WinToastTemplate::SecondLine);
	WinToast::WinToastError error;
	const auto succeeded = WinToast::instance()->initialize(&error);
	if (!succeeded) {
		std::wcout << L"Error, could not initialize the lib. Error number: "
			<< error << std::endl;
	}
	WinToastHandlerExample* handler = new WinToastHandlerExample;
	const auto toast_id = WinToast::instance()->showToast(templ, handler, &error);
	if (toast_id < 0) {
		std::wcout << L"Error: Could not launch your toast notification!" << std::endl;
	}
}

void dumpHashes(vector<string> files, string filename) {
	ofstream output(filename);
	if (!output.is_open()) {
		cout << "File could not be opened" << endl;
		return;
	}
	for (auto& f : files) {
		ifstream file(f, ios::binary);
		const auto hash = Botan::HashFunction::create_or_throw("SHA-256");
		std::vector<uint8_t> buf(4096);
		while (file.good()) {
			// read STDIN to buffer
			file.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
			const auto readcount = static_cast<size_t>(file.gcount());
			// update hash computations with read data
			hash->update(std::span{ buf }.first(readcount));
		}
		string SHAhex = Botan::hex_encode(hash->final());
		std::cout << "SHA-256: " << SHAhex << '\n';
		output << SHAhex << endl;
		file.close();
	}
}


map<string, string> generateHashes(vector<string> files) {
	map<string, string> hashes;
	for (auto& f : files) {
		ifstream file(f, ios::binary);
		const auto hash = Botan::HashFunction::create_or_throw("SHA-256");
		std::vector<uint8_t> buf(4096);
		while (file.good()) {
			// read STDIN to buffer
			file.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
			const auto readcount = static_cast<size_t>(file.gcount());
			// update hash computations with read data
			hash->update(std::span{ buf }.first(readcount));
		}
		//std::cout << "SHA-256: " << Botan::hex_encode(hash->final()) << '\n';
		hashes[f] = Botan::hex_encode(hash->final());
		file.close();
	}
	return hashes;
}

void scanFiles(vector<string> files, string fileHashesPath) {
	ifstream fileHashesContent(fileHashesPath);
	string currentHash;
	fileHashesContent >> currentHash;
	int currIndex = 0;
	while (fileHashesContent && currIndex < files.size()) {
		string currentFile = files.at(currIndex);
		cout << "Current File is " << currentFile << endl;
		ifstream file(currentFile, ios::binary);
		const auto newHash = Botan::HashFunction::create_or_throw("SHA-256");
		std::vector<uint8_t> buf(4096);
		while (file.good()) {
			// read STDIN to buffer
			file.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
			const auto readcount = static_cast<size_t>(file.gcount());
			// update hash computations with read data
			newHash->update(std::span{ buf }.first(readcount));
			string newHashHex = Botan::hex_encode(newHash->final());
			cout << "SHA-256: " << newHashHex << endl;
			if (newHashHex != currentHash) {
				popNotification(currentFile);
				cout << currentFile << " File hash changed" << endl;
				Sleep(5000);
			}
		} 
		currIndex++;
	}
	fileHashesContent.close();
}

int main(int argc, char* argv[]) {
	//popNotification("blank");
	vector<string> files = { "C:/Users/Admin/source/repos/file-integrity-monitor/test.txt", "C:/Users/Admin/source/repos/file-integrity-monitor/test2.txt"};
	string fileHashesPath = "hashes.txt";
	cout << "Menu" << endl;
	cout << "[0] Dump Hashes" << endl;
	cout << "[1] Scan Files" << endl;
	string input;
	cin >> input;
	if (input == "0") {
		dumpHashes(files, "hashes.txt");
	}
	else if (input == "1") {
		scanFiles(files, fileHashesPath);
	}
	else {
		cout << "Please enter a correct option." << endl;
		return 0;
	}
	//dumpHashes(files, "hashes.txt");
	//map<string, string> fileHashes = generateHashes(files);
	//scanFiles(files, fileHashesPath);
	//cout << "Hello, world!" << endl;
	//Sleep(3000);
}