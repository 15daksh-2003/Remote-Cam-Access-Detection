# Remote-Cam-Access-Detection

Remote-Cam Detection POC
1. Objective
Develop a proof-of-concept (POC) framework that simulates remote camera access attacks on Windows systems. The simulation mimics an advanced attack chain where an attacker deploys a single payload executable that creates a dedicated child process to load a malicious DLL. This DLL initializes its own Media Foundation capture session, registers a custom callback to capture and exfiltrate camera data over a persistent TCP/IP connection, and includes robust cleanup routines. A detection engine (to be implemented later) will concurrently monitor for anomalies. The new design ensures that the payload, once executed by a user, performs the intended attack and self-terminates, leaving minimal traces.
________________________________________
2. High-Level Overview
2.1. Realistic Attack Chain
The simulation now follows these revised steps:
1.	Centralized Payload Execution:
o	A single executable (e.g., RemoteCamAttack.exe) is launched by the user with command-line parameters (such as -runtime 30).
o	The parent process (the main executable) immediately creates a dedicated child process to handle the attack simulation.
2.	Child Process Responsibilities:
o	DLL Loading & Initialization:
	The child process loads the malicious DLL (e.g., using LoadLibrary() with a relative path such as "..\\malicious_dll\\malicious_dll.dll").
	Upon loading, the DLL’s DllMain automatically performs initialization:
	Initializes a Media Foundation capture session in asynchronous mode.
	Registers a custom callback (implementing IMFSourceReaderCallback) that intercepts camera frames.
	Establishes a persistent, thread-safe TCP/IP connection for exfiltrating captured frame data.
o	Operational Phase:
	The child process remains active for the specified runtime (as passed by the user), during which the DLL continues capturing and exfiltrating data.
o	Cleanup & Reversibility:
	Once the runtime elapses, the child process unloads the DLL (via FreeLibrary()) to trigger cleanup routines:
	Stopping the capture session.
	Closing the TCP/IP connection.
	Releasing allocated resources.
	The child process then terminates, ensuring that all modifications remain confined to its own memory space.
3.	Parent Process Responsibilities:
o	The parent process is responsible for:
	Process Creation:
	Spawning the child process (via CreateProcess()), passing the runtime parameter and a -child flag.
	Lifecycle Management & Logging:
	Continuously polling the child process (e.g., every 2 seconds) to log its state (running, terminated, etc.).
	Upon child termination, performing final cleanup (closing handles) and then exiting.
________________________________________
2.2. Detection Engine (Future Work)
•	Concurrent Monitoring:
o	A separate detection engine (running as a thread or separate process) will be integrated to:
	Log the baseline system state (e.g., expected function pointers and capture session details).
	Continuously monitor memory, network activity, and process behavior.
	Trigger alerts if unexpected modifications or anomalous behavior is detected.
o	The detection engine's design remains similar to the original but will be integrated concurrently with the new centralized payload execution.
________________________________________
3. Module-Level Design & Responsibilities
3.1. Malicious DLL Module
•	Camera Capture & Asynchronous Callback Registration:
o	The DLL, upon loading, initializes Media Foundation.
o	It creates an asynchronous capture session, sets the MF_SOURCE_READER_ASYNC_CALLBACK attribute, and registers its malicious callback.
•	Malicious Callback & Data Exfiltration:
o	Implements OnReadSample, OnFlush, and OnEvent with the proper signatures.
o	Extracts camera frame data and exfiltrates it via a persistent TCP/IP connection (synchronized with critical sections).
•	Cleanup & Reversibility:
o	The DLL defines explicit cleanup routines to stop the capture session, close the TCP/IP connection, and free resources.
o	These routines are triggered by unloading the DLL (via FreeLibrary()).
3.2. Centralized Payload (RemoteCamAttack.exe)
•	Parent Process:
o	Parses command-line arguments (e.g., -runtime 30).
o	Creates a child process (spawning the same executable with a -child flag and runtime parameter).
o	Logs creation, periodically checks the status of the child process, and cleans up once the child terminates.
•	Child Process:
o	Recognizes the -child flag and:
	Loads the malicious DLL.
	Sleeps for the specified runtime period.
	Unloads the DLL to trigger cleanup routines.
	Exits gracefully after logging all relevant events.
3.3. Integration and Orchestration
•	Isolation & Process-Specific Behavior:
o	All malicious operations (capture, exfiltration, and DLL-specific hooks) are contained within the child process, ensuring that any modifications do not affect the entire system.
•	Robust Logging & Monitoring:
o	Both parent and child processes log their states at every step, including process creation, DLL load/unload events, and cleanup operations.
•	Command-Line Driven Execution:
o	The runtime parameter is provided at launch and passed to the child process, making the duration of the simulation flexible and user-controlled.
•	Future Integration with Detection Engine:
o	The detection engine module can be integrated to run concurrently with the payload, analyzing system state in real time and supporting forensic analysis.
________________________________________
4. Integration and Testing Strategy
4.1. Environment Setup
•	Isolation:
o	The entire simulation should be executed within a Virtual Machine (VM) or container to prevent unintended modifications to the host system.
•	Test Harness:
o	The centralized payload executable (RemoteCamAttack.exe) serves as the test harness, orchestrating both the attack simulation (via the child process) and logging its lifecycle.
4.2. Test Cases
•	Baseline Test:
o	Run the executable with no DLL injection to ensure baseline system behavior is logged.
•	Attack Simulation Test:
o	Launch RemoteCamAttack.exe with a runtime parameter (e.g., -runtime 30) and verify that:
	A child process is created.
	The malicious DLL is loaded, initializes the capture session, and exfiltrates data.
	Proper logging occurs at every stage.
•	Reversibility Test:
o	Verify that after the runtime expires:
	The DLL is properly unloaded.
	Cleanup routines restore the system to its baseline state.
	The child process terminates gracefully.
•	Detection Engine Test (Future):
o	Validate that a separate detection engine (once implemented) correctly logs baseline state and flags anomalies.
4.3. Verification Metrics
•	Capture and Exfiltration Metrics:
o	Verify that the expected number of frames are captured and exfiltrated.
•	Process and Memory Footprint:
o	Ensure that the attack simulation is confined to the child process and that all resources are released upon termination.
•	Log Accuracy:
o	Confirm that all log entries (process creation, DLL load/unload, cleanup events) match the expected behavior as per the design.
________________________________________
5. Summary
The revised design now reflects the following enhancements over the original design:
•	Unified Executable Approach:
o	The functionality previously divided between a separate loader executable and an attack simulation thread is now merged into a single payload executable (RemoteCamAttack.exe).
•	Child Process Isolation:
o	The payload creates a dedicated child process that handles all malicious operations (loading the DLL, running capture/exfiltration, cleanup), ensuring isolation from the parent process.
•	Command-Line Control:
o	A user-defined runtime parameter controls the duration of the simulation, with the child process receiving and acting on this parameter.
•	Robust Logging and Lifecycle Management:
o	Detailed logging throughout the lifecycle—from process creation and DLL load/unload to cleanup—ensures full transparency and traceability of operations.
•	Reversibility and Minimal Footprint:
o	The design ensures that after execution, all modifications are cleaned up, and the process terminates by itself, closely mimicking a real-world attack scenario where the attacker’s payload self-destructs after completing its objective.
•	Forward Compatibility with Detection Engine:
o	The design leaves room for future integration with a detection engine that will run concurrently to monitor for anomalies and support forensic analysis.

