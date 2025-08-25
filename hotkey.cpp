#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

#include <memory>
#include <optional>
#include <shlobj.h>
#include <system_error>
#include <windows.h>

constexpr UINT WM_PROCESS_HOTKEY = WM_APP + 1;

DWORD g_mainThreadId = 0;
HHOOK g_hHook = nullptr;

inline void ThrowIfFailed(HRESULT hr, const char *msg) {
	if (FAILED(hr))
		throw std::system_error{hr, std::system_category(), msg};
}

struct ComInitializer {
	constexpr ComInitializer(DWORD coInit = COINIT_APARTMENTTHREADED) {
		ThrowIfFailed(CoInitializeEx(nullptr, coInit), "CoInitializeEx failed");
	}
	constexpr ~ComInitializer() { CoUninitialize(); }
	consteval ComInitializer(const ComInitializer &) = delete;
	consteval ComInitializer &operator=(const ComInitializer &) = delete;
};

struct HookGuard {
	constexpr HookGuard(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
		g_hHook = SetWindowsHookEx(idHook, lpfn, hmod, dwThreadId);
		if (!g_hHook)
			throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "SetWindowsHookEx failed");
	}
	constexpr ~HookGuard() {
		if (g_hHook)
			UnhookWindowsHookEx(g_hHook);
	}
	consteval HookGuard(const HookGuard &) = delete;
	consteval HookGuard &operator=(const HookGuard &) = delete;
};

constexpr auto CoTaskMemDeleter = [](void *p) { if (p) CoTaskMemFree(p); };
using UniqueItemIDList = std::unique_ptr<ITEMIDLIST, decltype(CoTaskMemDeleter)>;
using UniqueCoTaskMemString = std::unique_ptr<wchar_t, decltype(CoTaskMemDeleter)>;

constexpr auto HandleDeleter = [](HANDLE h) { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); };
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(HandleDeleter)>;

auto IsExplorerWindow(HWND hwnd) {
	wchar_t className[256];
	if (GetClassNameW(hwnd, className, ARRAYSIZE(className))) {
		return wcscmp(className, L"CabinetWClass") == 0;
	}
	return false;
}

std::optional<UniqueItemIDList> GetExplorerFolderPidl(HWND targetHwnd) {
	IShellWindows *pshWindows = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_ShellWindows, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pshWindows));
	ThrowIfFailed(hr, "Could not create instance of IShellWindows");

	long count = 0;
	hr = pshWindows->get_Count(&count);
	if (FAILED(hr)) {
		pshWindows->Release();
		ThrowIfFailed(hr, "Could not get number of shell windows");
	}

	std::optional<UniqueItemIDList> result = std::nullopt;

	for (long i = 0; i < count && !result; ++i) {
		IDispatch *pDisp = nullptr;
		IWebBrowserApp *pApp = nullptr;
		IServiceProvider *psp = nullptr;
		IShellBrowser *pBrowser = nullptr;
		IShellView *pShellView = nullptr;
		IFolderView *pFolderView = nullptr;
		IPersistFolder2 *pFolder = nullptr;

		auto cleanup_loop_item = [&]() {
			if (pFolder)
				pFolder->Release();
			if (pFolderView)
				pFolderView->Release();
			if (pShellView)
				pShellView->Release();
			if (pBrowser)
				pBrowser->Release();
			if (psp)
				psp->Release();
			if (pApp)
				pApp->Release();
			if (pDisp)
				pDisp->Release();
		};

		VARIANT vi;
		VariantInit(&vi);
		vi.vt = VT_I4;
		vi.lVal = i;
		hr = pshWindows->Item(vi, &pDisp);
		VariantClear(&vi);
		if (FAILED(hr) || !pDisp) {
			continue;
		}

		hr = pDisp->QueryInterface(IID_PPV_ARGS(&pApp));
		if (FAILED(hr) || !pApp) {
			cleanup_loop_item();
			continue;
		}

		HWND hwnd = nullptr;
		pApp->get_HWND(reinterpret_cast<SHANDLE_PTR *>(&hwnd));
		if (hwnd != targetHwnd) {
			cleanup_loop_item();
			continue;
		}

		hr = pApp->QueryInterface(IID_PPV_ARGS(&psp));
		if (FAILED(hr) || !psp) {
			cleanup_loop_item();
			continue;
		}

		hr = psp->QueryService(SID_STopLevelBrowser, IID_PPV_ARGS(&pBrowser));
		if (FAILED(hr) || !pBrowser) {
			cleanup_loop_item();
			continue;
		}

		hr = pBrowser->QueryActiveShellView(&pShellView);
		if (FAILED(hr) || !pShellView) {
			cleanup_loop_item();
			continue;
		}

		hr = pShellView->QueryInterface(IID_PPV_ARGS(&pFolderView));
		if (FAILED(hr) || !pFolderView) {
			cleanup_loop_item();
			continue;
		}

		hr = pFolderView->GetFolder(IID_PPV_ARGS(&pFolder));
		if (FAILED(hr) || !pFolder) {
			cleanup_loop_item();
			continue;
		}

		ITEMIDLIST *pidl = nullptr;
		if (SUCCEEDED(pFolder->GetCurFolder(&pidl))) {
			result.emplace(pidl);
		}

		cleanup_loop_item();
	}

	pshWindows->Release();
	return result;
}

void HandleHotkey() {
	const auto fg = GetForegroundWindow();
	if (!fg || !IsExplorerWindow(fg))
		return;

	if (auto pidlOpt = GetExplorerFolderPidl(fg)) {
		wchar_t *pPathRaw = nullptr;
		if (SUCCEEDED(SHGetNameFromIDList(pidlOpt->get(), SIGDN_FILESYSPATH, &pPathRaw))) {
			auto pPath = UniqueCoTaskMemString(pPathRaw);

			std::wstring pathStr = pPath.get();
			if (!pathStr.empty() && pathStr.back() == '\\') {
				pathStr.pop_back();
			}

			auto params = L"-d \"" + pathStr + L"/\""; // Added trailing slash to ensure this works

			SHELLEXECUTEINFOW sei = {sizeof(SHELLEXECUTEINFOW)}; // NOLINT
			sei.lpVerb = L"open";
			sei.lpFile = L"wt.exe";
			sei.lpParameters = params.c_str();
			sei.nShow = SW_SHOWNORMAL;
			ShellExecuteExW(&sei);
		}
	}
}

auto CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
		auto *p = reinterpret_cast<KBDLLHOOKSTRUCT *>(lParam);
		if (p->vkCode == VK_OEM_3 && (GetAsyncKeyState(VK_CONTROL) & 0x8000))
			PostThreadMessage(g_mainThreadId, WM_PROCESS_HOTKEY, 0, 0);
	}
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
	g_mainThreadId = GetCurrentThreadId();
	try {
		ComInitializer coInit;
		HookGuard hook(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(nullptr), 0);

		MSG msg;
		while (GetMessage(&msg, nullptr, 0, 0) > 0) {
			if (msg.message == WM_PROCESS_HOTKEY)
				HandleHotkey();
		}
		return static_cast<int>(msg.wParam);
	} catch (...) {
		return EXIT_FAILURE;
	}
}
