////////////////////////////////////////////////////////////
// Oculus Monitor
// Copyright (C) 2018 Kojack (rajetic@gmail.com)
//
// KF is released under the MIT License  
// https://opensource.org/licenses/MIT
////////////////////////////////////////////////////////////

// Parts of this file are based on the DirectX 11 sample that comes with ImGui.

#define NOMINMAX
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>
#include <tchar.h>
#include <iostream>
#include "OVR_Platform.h"
#include "OVR_CAPI.h"
#include "Extras/OVR_Math.h"
#include <vector>
#include <algorithm>
#include "kf/kf_time.h"
#include <fstream>
#include "vrstate.h"
#include "aabb.h"

#pragma comment(lib,"LibOVR.lib")

// Data
static ID3D11Device*            g_pd3dDevice = NULL;
static ID3D11DeviceContext*     g_pd3dDeviceContext = NULL;
static IDXGISwapChain*          g_pSwapChain = NULL;
static ID3D11RenderTargetView*  g_mainRenderTargetView = NULL;
ovrSession						g_HMD = 0;
bool							g_minimised = false;

void CreateRenderTarget()
{
	ID3D11Texture2D* pBackBuffer;
	g_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
	g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
	pBackBuffer->Release();
}

void CleanupRenderTarget()
{
	if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

HRESULT CreateDeviceD3D(HWND hWnd)
{
	// Setup swap chain
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 90;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hWnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	//createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
		return E_FAIL;

	CreateRenderTarget();

	return S_OK;
}

void CleanupDeviceD3D()
{
	CleanupRenderTarget();
	if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
	if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
	if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;
	std::cout << msg << std::endl;
	switch (msg)
	{
	case WM_PAINT:
		g_minimised = false;
		break;
	case WM_SIZE:
		if (wParam == SIZE_MINIMIZED)
		{
			g_minimised = true;
		}
		else
		{
			if (g_pd3dDevice != NULL)
			{
				ImGui_ImplDX11_InvalidateDeviceObjects();
				CleanupRenderTarget();
				g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
				CreateRenderTarget();
				ImGui_ImplDX11_CreateDeviceObjects();
			}
		}
		if (wParam == SIZE_RESTORED)
		{
			g_minimised = false;
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
			return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

void appendstring(std::string &s, const std::string &a)
{
	if (s != "")
	{
		s += ", ";
	}
	s += a;
}


int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	// Create application window
	WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, _T("Oculus Monitor"), NULL };
	RegisterClassEx(&wc);
	HWND hwnd = CreateWindow(_T("Oculus Monitor"), _T("Oculus Monitor"), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, NULL, NULL, wc.hInstance, NULL);
	int sss = sizeof(VRState);
	StateManager stateManager;
	float currentTime = 0;
	kf::Time timer;
	bool paused = false;

	// Initialize Direct3D
	if (CreateDeviceD3D(hwnd) < 0)
	{
		CleanupDeviceD3D();
		UnregisterClass(_T("Oculus Monitor"), wc.hInstance);
		return 1;
	}

	// Show the window
	ShowWindow(hwnd, SW_SHOWDEFAULT);
	UpdateWindow(hwnd);

	// Setup Dear ImGui binding
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;

	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

	// Setup style
	ImGui::StyleColorsDark();

	ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
	bool showSerial = false;
	int currentHudMode = 0;
	bool showSensors = true;
	float pixelDensity = 1.0f;
	bool trackingFloorLevel = true;

	ovrGraphicsLuid g_luid;
	ovrInitParams params;
	params.Flags = ovrInit_Invisible;
	params.ConnectionTimeoutMS = 0;
	params.RequestedMinorVersion = 26;
	params.UserData = 0;
	params.LogCallback = 0;

	ovrResult result = ovr_Initialize(&params);
	if (OVR_FAILURE(result))
		return 1;

	result = ovr_Create(&g_HMD, &g_luid);

	ovr_SetTrackingOriginType(g_HMD, ovrTrackingOrigin::ovrTrackingOrigin_FloorLevel);

	currentHudMode = ovr_GetInt(g_HMD, OVR_PERF_HUD_MODE, 0);

	// Main loop
	MSG msg;
	ZeroMemory(&msg, sizeof(msg));
	while (msg.message != WM_QUIT)
	{
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}

		double deltaT = timer.deltaTime();

		if (!IsIconic(hwnd))
		{
			// Start the Dear ImGui frame
			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();

			if (g_HMD)
			{
				VRState state = stateManager.poll(g_HMD, currentTime);
				
				// Record/Playback
				{
					ImGui::Begin("Playback");
					if (stateManager.m_pollState == StateManager::e_record)
					{
						ImGui::PushStyleColor(ImGuiCol_Button, 0xffff0000);
						if (ImGui::Button("Record"))
						{
							stateManager.m_pollState = StateManager::e_live;
						}
						ImGui::PopStyleColor();
					}
					else
					{
						if (ImGui::Button("Record"))
						{
							stateManager.reset();
							stateManager.m_pollState = StateManager::e_record;
							currentTime = 0;
						}
					}
					ImGui::SameLine();
					if (stateManager.m_pollState == StateManager::e_playback)
					{
						ImGui::PushStyleColor(ImGuiCol_Button, 0xffff0000);
						if (ImGui::Button("Play"))
						{
							stateManager.m_pollState = StateManager::e_live;
						}
						ImGui::PopStyleColor();
					}
					else
					{
						if (ImGui::Button("Play"))
						{
							currentTime = 0;
							stateManager.m_pollState = StateManager::e_playback;
						}
					}

					ImGui::SameLine();
					if (ImGui::Button("Stop"))
					{
						stateManager.m_pollState = StateManager::e_live;
					}

					ImGui::SameLine();
					if (paused)
					{
						ImGui::PushStyleColor(ImGuiCol_Button, 0xffff0000);
						if (ImGui::Button("Pause"))
						{
							paused = false;
						}
						ImGui::PopStyleColor();
					}
					else
					{
						if (ImGui::Button("Pause"))
						{
							paused = true;
						}
					}
					if (!stateManager.m_samples.empty())
					{
						if (ImGui::Button("Export CSV"))
						{
							char filename[MAX_PATH];

							OPENFILENAME ofn;
							ZeroMemory(&filename, sizeof(filename));
							ZeroMemory(&ofn, sizeof(ofn));
							ofn.lStructSize = sizeof(ofn);
							ofn.hwndOwner = hwnd;
							ofn.lpstrFilter = "CSV Files\0*.csv\0Any File\0*.*\0";
							ofn.lpstrFile = filename;
							ofn.nMaxFile = MAX_PATH;
							ofn.lpstrTitle = "Select destination for export";
							ofn.Flags = OFN_NOCHANGEDIR;

							if (GetSaveFileNameA(&ofn))
							{
								stateManager.exportCSV(filename);
							}
						}
						if (ImGui::Button("Export DAE"))
						{
							char filename[MAX_PATH];

							OPENFILENAME ofn;
							ZeroMemory(&filename, sizeof(filename));
							ZeroMemory(&ofn, sizeof(ofn));
							ofn.lStructSize = sizeof(ofn);
							ofn.hwndOwner = hwnd;
							ofn.lpstrFilter = "DAE Files\0*.dae\0Any File\0*.*\0";
							ofn.lpstrFile = filename;
							ofn.nMaxFile = MAX_PATH;
							ofn.lpstrTitle = "Select destination for export";
							ofn.Flags = OFN_NOCHANGEDIR;

							if (GetSaveFileNameA(&ofn))
							{
								stateManager.exportDAE(g_HMD, filename);
							}
						}
					}


					switch (stateManager.m_pollState)
					{
					case StateManager::e_playback:
						ImGui::LabelText("Mode", "Playback");
						if(!paused)
							currentTime += deltaT;
						break;
					case StateManager::e_record:
						ImGui::LabelText("Mode", "Recording");
						if (!paused)
							currentTime += deltaT;
						break;
					case StateManager::e_live:
						ImGui::LabelText("Mode", "Live");
						break;
					}

					if (!stateManager.m_samples.empty())
					{
						ImGui::LabelText("Recorded", "%0.2fs", stateManager.m_samples.back().time);
						if (stateManager.m_pollState != StateManager::e_record)
						{
							if (currentTime > stateManager.m_samples.back().time)
								currentTime = stateManager.m_samples.back().time;
							ImGui::SliderFloat("Time", &currentTime, 0, stateManager.m_samples.back().time);
						}
					}
					ImGui::End();
				}

				// Headset
				{
					auto hmddesc = ovr_GetHmdDesc(g_HMD);
					ImGui::Begin("Headset");
					ImGui::Checkbox("Show Serial", &showSerial);
					if (showSerial)
						ImGui::LabelText("Serial", hmddesc.SerialNumber);
					ImGui::LabelText("Manufacturer", hmddesc.Manufacturer);
					ImGui::LabelText("Firmware", "%d.%d", (int)hmddesc.FirmwareMajor, (int)hmddesc.FirmwareMinor);
					ImGui::LabelText("Product", hmddesc.ProductName);
					if ((hmddesc.AvailableHmdCaps&ovrHmdCap_DebugDevice))
						ImGui::Text("Headset is a virtual debug device");
					std::string s;
					if (hmddesc.AvailableTrackingCaps&ovrTrackingCap_Orientation)
						appendstring(s, "Orientation");
					if (hmddesc.AvailableTrackingCaps&ovrTrackingCap_MagYawCorrection)
						appendstring(s, "Mag Yaw Correction");
					if (hmddesc.AvailableTrackingCaps&ovrTrackingCap_Position)
						appendstring(s, "Position");
					ImGui::LabelText("Tracking Cap", s.c_str());
					s = "";
					if (state.trackingState.StatusFlags & ovrStatus_OrientationTracked)
					{
						appendstring(s, "Orientation");
					}
					if (state.trackingState.StatusFlags & ovrStatus_PositionTracked)
					{
						appendstring(s, "Position");
					}
					if (ImGui::Checkbox("Floor level tracking", &trackingFloorLevel))
					{
						ovr_SetTrackingOriginType(g_HMD, trackingFloorLevel?ovrTrackingOrigin::ovrTrackingOrigin_FloorLevel: ovrTrackingOrigin::ovrTrackingOrigin_EyeLevel);
					}
					ImGui::LabelText("Tracking", s.c_str());
					ImGui::LabelText("Pos", "%0.2f, %0.2f, %0.2f", state.trackingState.HeadPose.ThePose.Position.x, state.trackingState.HeadPose.ThePose.Position.y, state.trackingState.HeadPose.ThePose.Position.z);
					ImGui::LabelText("Orientation", "%0.2f, %0.2f, %0.2f, %0.2f", state.trackingState.HeadPose.ThePose.Orientation.w, state.trackingState.HeadPose.ThePose.Orientation.x, state.trackingState.HeadPose.ThePose.Orientation.y, state.trackingState.HeadPose.ThePose.Orientation.z);
					ImGui::LabelText("Vel", "%0.2f, %0.2f, %0.2f", state.trackingState.HeadPose.LinearVelocity.x, state.trackingState.HeadPose.LinearVelocity.y, state.trackingState.HeadPose.LinearVelocity.z);
					ImGui::LabelText("Panel Resolution", "%d x %d", hmddesc.Resolution.w, hmddesc.Resolution.h);
					ImGui::LabelText("LIBOVRRT Version", ovr_GetVersionString());
					const char *hudModes[] = { "None", "PerfSummary", "LatencyTiming", "AppRenderTiming", "CompRenderTiming", "VersionInfo", "AswStats" };
					if (ImGui::Combo("Hud Mode", &currentHudMode, hudModes, 7))
					{
						ovr_SetInt(g_HMD, OVR_PERF_HUD_MODE, currentHudMode);
					}
					ImGui::SliderFloat("Pixel Density", &pixelDensity, 0.1, 5.0);
					
					ovrSizei texSize = ovr_GetFovTextureSize(g_HMD, ovrEyeType::ovrEye_Left, hmddesc.DefaultEyeFov[0], pixelDensity);
					ImGui::LabelText("Render Resolution", "%d x %d  (%0.2fMp)", texSize.w, texSize.h, (texSize.w * texSize.h) / 1000000.0f);
					ImGui::End();
				}

				// Controllers
				{
					ImGui::Begin("Controllers");
					unsigned int connected = ovr_GetConnectedControllerTypes(g_HMD);
					bool conn_left = connected & ovrControllerType::ovrControllerType_LTouch;
					bool conn_right = connected & ovrControllerType::ovrControllerType_RTouch;
					bool conn_remote = connected & ovrControllerType::ovrControllerType_Remote;
					bool conn_xbox = connected & ovrControllerType::ovrControllerType_XBox;
					bool conn_object0 = connected & ovrControllerType::ovrControllerType_Object0;
					bool conn_object1 = connected & ovrControllerType::ovrControllerType_Object1;
					bool conn_object2 = connected & ovrControllerType::ovrControllerType_Object2;
					bool conn_object3 = connected & ovrControllerType::ovrControllerType_Object3;

					ImGui::Checkbox("Left connected", &conn_left);
					ImGui::Checkbox("Right connected", &conn_right);
					ImGui::Checkbox("Remote connected", &conn_remote);
					ImGui::Checkbox("XBox connected", &conn_xbox);
					ImGui::Checkbox("VR Object 0 connected", &conn_object0);
					ImGui::Checkbox("VR Object 1 connected", &conn_object1);
					ImGui::Checkbox("VR Object 2 connected", &conn_object2);
					ImGui::Checkbox("VR Object 3 connected", &conn_object3);

					ImGui::End();
					
					if (conn_object0)
					{
						ImGui::Begin("VR Object 0");
						ovrTrackedDeviceType types[4] = { ovrTrackedDeviceType::ovrTrackedDevice_Object0, ovrTrackedDeviceType::ovrTrackedDevice_Object1, ovrTrackedDeviceType::ovrTrackedDevice_Object2, ovrTrackedDeviceType::ovrTrackedDevice_Object3 };
						ovrPoseStatef poses[4];
						ovr_GetDevicePoses(g_HMD, types, 4, 0, poses);
						//ImGui::LabelText("Tracking", s.c_str());
						ImGui::LabelText("Pos", "%0.2f, %0.2f, %0.2f", poses[0].ThePose.Position.x, poses[0].ThePose.Position.y, poses[0].ThePose.Position.z);
						ImGui::LabelText("Orientation", "%0.2f, %0.2f, %0.2f, %0.2f", poses[0].ThePose.Orientation.w, poses[0].ThePose.Orientation.x, poses[0].ThePose.Orientation.y, poses[0].ThePose.Orientation.z);
						ImGui::LabelText("Vel", "%0.2f, %0.2f, %0.2f", poses[0].LinearVelocity.x, poses[0].LinearVelocity.y, poses[0].LinearVelocity.z);


						ImGui::End();
					}
					//ovrInputState instate;
					if (conn_remote)
					{
						//result = ovr_GetInputState(g_HMD, ovrControllerType_Remote, &instate);
						ImGui::Begin("Remote");
						bool remoteLeft = state.remoteButtons & ovrButton_Left;
						bool remoteRight = state.remoteButtons & ovrButton_Right;
						bool remoteUp = state.remoteButtons & ovrButton_Up;
						bool remoteDown = state.remoteButtons & ovrButton_Down;
						bool remoteEnter = state.remoteButtons & ovrButton_Enter;
						bool remoteBack = state.remoteButtons & ovrButton_Back;
						ImGui::Checkbox("Up", &remoteUp);
						ImGui::Checkbox("Down", &remoteDown);
						ImGui::Checkbox("Left", &remoteLeft);
						ImGui::Checkbox("Right", &remoteRight);
						ImGui::Checkbox("Enter", &remoteEnter);
						ImGui::Checkbox("Back", &remoteBack);
						ImGui::End();
					}

					//result = ovr_GetInputState(g_HMD, ovrControllerType_Touch, &instate);
					if (conn_left)
					{
						ImGui::Begin("Left Touch");
						ImGui::SliderFloat("Index", &state.touchIndexTrigger[0], 0.0f, 1.0f);
						ImGui::SliderFloat("IndexNDZ", &state.touchIndexTriggerNDZ[0], 0.0f, 1.0f);
						ImGui::SliderFloat("IndexRaw", &state.touchIndexTriggerRaw[0], 0.0f, 1.0f);
						ImGui::SliderFloat("Hand", &state.touchHandTrigger[0], 0.0f, 1.0f);
						ImGui::SliderFloat("HandNDZ", &state.touchHandTriggerNDZ[0], 0.0f, 1.0f);
						ImGui::SliderFloat("HandRaw", &state.touchHandTriggerRaw[0], 0.0f, 1.0f);
						ImGui::SliderFloat("Thumb X", &state.touchThumbStick[0].x, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb X NDZ", &state.touchThumbStickNDZ[0].x, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb X Raw", &state.touchThumbStickRaw[0].x, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb Y", &state.touchThumbStick[0].y, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb Y NDZ", &state.touchThumbStickNDZ[0].y, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb Y Raw", &state.touchThumbStickRaw[0].y, -1.0f, 1.0f);
						bool buttonX = state.touchButtons & ovrButton_X;
						bool buttonY = state.touchButtons & ovrButton_Y;
						bool buttonThumb = state.touchButtons & ovrButton_LThumb;
						bool buttonMenu = state.touchButtons & ovrButton_Enter;
						ImGui::Text("Buttons");
						ImGui::Checkbox("X", &buttonX);
						ImGui::Checkbox("Y", &buttonY);
						ImGui::Checkbox("Thumb", &buttonThumb);
						ImGui::Checkbox("Menu", &buttonMenu);
						bool touchX = state.touchTouch & ovrTouch_X;
						bool touchY = state.touchTouch & ovrTouch_Y;
						bool touchThumb = state.touchTouch & ovrTouch_LThumb;
						bool touchPad = state.touchTouch & ovrTouch_LThumbRest;
						bool touchIndex = state.touchTouch & ovrTouch_LIndexTrigger;
						bool touchPoint = state.touchTouch & ovrTouch_LIndexPointing;
						bool touchThumbUp = state.touchTouch & ovrTouch_LThumbUp;
						ImGui::Text("Touches");
						ImGui::Checkbox("X", &touchX);
						ImGui::Checkbox("Y", &touchY);
						ImGui::Checkbox("Thumb", &touchThumb);
						ImGui::Checkbox("Pad", &touchPad);
						ImGui::Checkbox("Index", &touchIndex);
						ImGui::Checkbox("Point", &touchPoint);
						ImGui::Checkbox("Thumbs Up", &touchThumbUp);
						std::string s;
						if (state.trackingState.HandStatusFlags[0] & ovrStatus_OrientationTracked)
						{
							appendstring(s, "Orientation");
						}
						if (state.trackingState.HandStatusFlags[0] & ovrStatus_PositionTracked)
						{
							appendstring(s, "Position");
						}
						ImGui::LabelText("Tracking", s.c_str());
						ImGui::LabelText("Pos", "%0.2f, %0.2f, %0.2f", state.trackingState.HandPoses[0].ThePose.Position.x, state.trackingState.HandPoses[0].ThePose.Position.y, state.trackingState.HandPoses[0].ThePose.Position.z);
						ImGui::LabelText("Orientation", "%0.2f, %0.2f, %0.2f, %0.2f", state.trackingState.HandPoses[0].ThePose.Orientation.w, state.trackingState.HandPoses[0].ThePose.Orientation.x, state.trackingState.HandPoses[0].ThePose.Orientation.y, state.trackingState.HandPoses[0].ThePose.Orientation.z);
						ImGui::LabelText("Vel", "%0.2f, %0.2f, %0.2f", state.trackingState.HandPoses[0].LinearVelocity.x, state.trackingState.HandPoses[0].LinearVelocity.y, state.trackingState.HandPoses[0].LinearVelocity.z);

						ImGui::End();
					}
					if (conn_right)
					{
						ImGui::Begin("Right Touch");
						ImGui::SliderFloat("Index", &state.touchIndexTrigger[1], 0.0f, 1.0f);
						ImGui::SliderFloat("IndexNDZ", &state.touchIndexTriggerNDZ[1], 0.0f, 1.0f);
						ImGui::SliderFloat("IndexRaw", &state.touchIndexTriggerRaw[1], 0.0f, 1.0f);
						ImGui::SliderFloat("Hand", &state.touchHandTrigger[1], 0.0f, 1.0f);
						ImGui::SliderFloat("HandNDZ", &state.touchHandTriggerNDZ[1], 0.0f, 1.0f);
						ImGui::SliderFloat("HandRaw", &state.touchHandTriggerRaw[1], 0.0f, 1.0f);
						ImGui::SliderFloat("Thumb X", &state.touchThumbStick[1].x, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb X NDZ", &state.touchThumbStickNDZ[1].x, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb X Raw", &state.touchThumbStickRaw[1].x, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb Y", &state.touchThumbStick[1].y, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb Y NDZ", &state.touchThumbStickNDZ[1].y, -1.0f, 1.0f);
						ImGui::SliderFloat("Thumb Y Raw", &state.touchThumbStickRaw[1].y, -1.0f, 1.0f);
						bool buttonA = state.touchButtons & ovrButton_A;
						bool buttonB = state.touchButtons & ovrButton_B;
						bool buttonThumb = state.touchButtons & ovrButton_RThumb;
						bool buttonHome = state.touchButtons & ovrButton_Home;
						ImGui::Text("Buttons");
						ImGui::Checkbox("A", &buttonA);
						ImGui::Checkbox("B", &buttonB);
						ImGui::Checkbox("Thumb", &buttonThumb);
						ImGui::Checkbox("Home", &buttonHome);
						bool touchA = state.touchTouch & ovrTouch_A;
						bool touchB = state.touchTouch & ovrTouch_B;
						bool touchThumb = state.touchTouch & ovrTouch_RThumb;
						bool touchPad = state.touchTouch & ovrTouch_RThumbRest;
						bool touchIndex = state.touchTouch & ovrTouch_RIndexTrigger;
						bool touchPoint = state.touchTouch & ovrTouch_RIndexPointing;
						bool touchThumbUp = state.touchTouch & ovrTouch_RThumbUp;
						ImGui::Text("Touches");
						ImGui::Checkbox("A", &touchA);
						ImGui::Checkbox("B", &touchB);
						ImGui::Checkbox("Thumb", &touchThumb);
						ImGui::Checkbox("Pad", &touchPad);
						ImGui::Checkbox("Index", &touchIndex);
						ImGui::Checkbox("Point", &touchPoint);
						ImGui::Checkbox("Thumbs Up", &touchThumbUp);
						std::string s;
						if (state.trackingState.HandStatusFlags[1] & ovrStatus_OrientationTracked)
						{
							appendstring(s, "Orientation");
						}
						if (state.trackingState.HandStatusFlags[1] & ovrStatus_PositionTracked)
						{
							appendstring(s, "Position");
						}
						ImGui::LabelText("Tracking", s.c_str());
						ImGui::LabelText("Pos", "%0.2f, %0.2f, %0.2f", state.trackingState.HandPoses[1].ThePose.Position.x, state.trackingState.HandPoses[1].ThePose.Position.y, state.trackingState.HandPoses[1].ThePose.Position.z);
						ImGui::LabelText("Orientation", "%0.2f, %0.2f, %0.2f, %0.2f", state.trackingState.HandPoses[1].ThePose.Orientation.w, state.trackingState.HandPoses[1].ThePose.Orientation.x, state.trackingState.HandPoses[1].ThePose.Orientation.y, state.trackingState.HandPoses[1].ThePose.Orientation.z);
						ImGui::LabelText("Vel", "%0.2f, %0.2f, %0.2f", state.trackingState.HandPoses[1].LinearVelocity.x, state.trackingState.HandPoses[1].LinearVelocity.y, state.trackingState.HandPoses[1].LinearVelocity.z);
						ImGui::End();
					}
				}
				{
					ImGui::Begin("Room Layout");
					ImGui::Checkbox("Show Sensors", &showSensors);

					AABB aabb;
					ImVec2 size = ImGui::GetContentRegionMax();
					ImVec2 offset = ImGui::GetWindowPos();
					int outerCount = 0;
					int playCount = 0;
					ovr_GetBoundaryGeometry(g_HMD, ovrBoundaryType::ovrBoundary_Outer, 0, &outerCount);
					ovr_GetBoundaryGeometry(g_HMD, ovrBoundaryType::ovrBoundary_PlayArea, 0, &playCount);

					std::vector<ovrVector3f> outerPoints3d(outerCount);
					std::vector<ovrVector3f> playPoints3d(playCount);

					if (outerCount > 0)
					{
						ovr_GetBoundaryGeometry(g_HMD, ovrBoundaryType::ovrBoundary_Outer, &(outerPoints3d[0]), &outerCount);
						for (int i = 0; i < outerCount; ++i)
						{
							aabb.merge(outerPoints3d[i]);
						}
					}

					if (playCount > 0)
					{
						ovr_GetBoundaryGeometry(g_HMD, ovrBoundaryType::ovrBoundary_PlayArea, &(playPoints3d[0]), &playCount);
						for (int i = 0; i < playCount; ++i)
						{
							aabb.merge(playPoints3d[i]);
						}
					}

					if (showSensors)
					{
						for (int i = 0; i < state.sensorCount; ++i)
						{
							aabb.merge(state.sensorPose[i].LeveledPose.Position);
						}
					}

					aabb.minCorner -= OVR::Vector3f(0.2, 0.2, 0.2);
					aabb.maxCorner += OVR::Vector3f(0.2, 0.2, 0.2);

					std::vector<ImVec2> outerPoints2d(outerCount);
					std::vector<ImVec2> playPoints2d(playCount);

					for (int i = 0; i < outerCount; ++i)
					{
						outerPoints2d[i] = aabb.remap(size, offset, outerPoints3d[i]);
					}
					if (outerCount > 0)
					{
						ImGui::GetWindowDrawList()->AddPolyline(&outerPoints2d[0], outerCount, 0xffffffff, true, 1);
					}

					for (int i = 0; i < playCount; ++i)
					{
						playPoints2d[i] = aabb.remap(size, offset, playPoints3d[i]);
					}
					if (outerCount > 0)
					{
						ImGui::GetWindowDrawList()->AddPolyline(&playPoints2d[0], playCount, 0xffffff00, true, 1);
					}

					ImVec2 pos;
					ImVec2 pos1;
					ImVec2 pos2;
					ImVec2 pos3;
					ImVec2 pos4;

					pos = aabb.remap(size, offset, state.trackingState.HandPoses[0].ThePose.Position);
					ImGui::GetWindowDrawList()->AddCircle(pos, 10, 0xffffffff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HandPoses[0].ThePose.Position) + OVR::Quatf(state.trackingState.HandPoses[0].ThePose.Orientation) * OVR::Vector3f(0.2, 0, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff0000ff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HandPoses[0].ThePose.Position) + OVR::Quatf(state.trackingState.HandPoses[0].ThePose.Orientation) * OVR::Vector3f(0, 0.2, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff00ff00);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HandPoses[0].ThePose.Position) + OVR::Quatf(state.trackingState.HandPoses[0].ThePose.Orientation) * OVR::Vector3f(0, 0, -0.2));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xffff3030);

					pos = aabb.remap(size, offset, state.trackingState.HandPoses[1].ThePose.Position);
					ImGui::GetWindowDrawList()->AddCircle(pos, 10, 0xffffffff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HandPoses[1].ThePose.Position) + OVR::Quatf(state.trackingState.HandPoses[1].ThePose.Orientation) * OVR::Vector3f(0.2, 0, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff0000ff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HandPoses[1].ThePose.Position) + OVR::Quatf(state.trackingState.HandPoses[1].ThePose.Orientation) * OVR::Vector3f(0, 0.2, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff00ff00);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HandPoses[1].ThePose.Position) + OVR::Quatf(state.trackingState.HandPoses[1].ThePose.Orientation) * OVR::Vector3f(0, 0, -0.2));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xffff3030);

					pos = aabb.remap(size, offset, state.trackingState.HeadPose.ThePose.Position);
					ImGui::GetWindowDrawList()->AddCircle(pos, 10, 0xff00ffff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HeadPose.ThePose.Position) + OVR::Quatf(state.trackingState.HeadPose.ThePose.Orientation) * OVR::Vector3f(0.2, 0, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff0000ff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HeadPose.ThePose.Position) + OVR::Quatf(state.trackingState.HeadPose.ThePose.Orientation) * OVR::Vector3f(0, 0.2, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff00ff00);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.HeadPose.ThePose.Position) + OVR::Quatf(state.trackingState.HeadPose.ThePose.Orientation) * OVR::Vector3f(0, 0, -0.2));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xffff3030);

					pos = aabb.remap(size, offset, state.trackingState.CalibratedOrigin.Position);
					ImGui::GetWindowDrawList()->AddCircle(pos, 10, 0xff0000ff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.CalibratedOrigin.Position) + OVR::Quatf(state.trackingState.CalibratedOrigin.Orientation) * OVR::Vector3f(0.2, 0, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff0000ff);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.CalibratedOrigin.Position) + OVR::Quatf(state.trackingState.CalibratedOrigin.Orientation) * OVR::Vector3f(0, 0.2, 0));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xff00ff00);
					pos2 = aabb.remap(size, offset, OVR::Vector3f(state.trackingState.CalibratedOrigin.Position) + OVR::Quatf(state.trackingState.CalibratedOrigin.Orientation) * OVR::Vector3f(0, 0, -0.2));
					ImGui::GetWindowDrawList()->AddLine(pos, pos2, 0xffff3030);

					if (showSensors)
					{
						for (int i = 0; i < state.sensorCount; ++i)
						{
							//ovrTrackerDesc desc = ovr_GetTrackerDesc(g_HMD, i);
							//ovrTrackerPose pose = ovr_GetTrackerPose(g_HMD, i);
							float fov = state.sensorDesc[i].FrustumHFovInRadians / 2.0;
							pos = aabb.remap(size, offset, state.sensorPose[i].Pose.Position);
							ImGui::GetWindowDrawList()->AddCircle(pos, 10, 0xffff00ff);
							OVR::Quatf q = state.sensorPose[i].LeveledPose.Orientation;
							OVR::Vector3f dir = q * OVR::Vector3f(0, 0, 1);
							OVR::Vector3f dirPerp(-dir.z, dir.y, dir.x);
							float x = sin(fov);
							float y = cos(fov);
							float scaleNear = state.sensorDesc[i].FrustumNearZInMeters / y;
							float scaleFar = state.sensorDesc[i].FrustumFarZInMeters / y;

							pos1 = aabb.remap(size, offset, OVR::Vector3f(state.sensorPose[i].Pose.Position) + dir * y*scaleNear + dirPerp * -x * scaleNear);
							pos2 = aabb.remap(size, offset, OVR::Vector3f(state.sensorPose[i].Pose.Position) + dir * y*scaleNear + dirPerp * x*scaleNear);
							pos3 = aabb.remap(size, offset, OVR::Vector3f(state.sensorPose[i].Pose.Position) + dir * y*scaleFar + dirPerp * -x * scaleFar);
							pos4 = aabb.remap(size, offset, OVR::Vector3f(state.sensorPose[i].Pose.Position) + dir * y*scaleFar + dirPerp * x*scaleFar);

							ImGui::GetWindowDrawList()->AddQuadFilled(pos1, pos3, pos4, pos2, 0x20ff00ff);
							ImGui::GetWindowDrawList()->AddLine(pos, pos3, 0xffff00ff);
							ImGui::GetWindowDrawList()->AddLine(pos, pos4, 0xffff00ff);
						}
					}
					ImGui::End();
				}
			}
			else
			{
				ImGui::Begin("Error");
				ImGui::Text("Failed to create the session");
				ImGui::End();
			}

			// Rendering
			ImGui::Render();
			g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
			g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, (float*)&clear_color);
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

			g_pSwapChain->Present(1, 0); // Present with vsync
		}
		else
		{
			Sleep(100);
		}
	}

	ovr_Destroy(g_HMD);

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	CleanupDeviceD3D();
	DestroyWindow(hwnd);
	UnregisterClass(_T("Oculus Monitor"), wc.hInstance);

	return 0;
}
