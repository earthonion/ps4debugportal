import asyncio
import struct
import json
import time
import os
import sys
import socket
import ftplib
from io import BytesIO
from flask import Flask, render_template, request, jsonify, session, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import ps4debug
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import threading
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import webview

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ps4debug-secret-key-change-in-production'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state
class PS4Manager:
    def __init__(self):
        self.ps4: Optional[ps4debug.PS4Debug] = None
        self.connected = False
        self.current_pid = None
        self.processes = []
        self.scan_results = {}
        self.breakpoints = {}
        self.debugger = None
        self.debugger_context = None
        self.debugger_active = False
        self.debugger_task = None
        self.breakpoint_hits = []
        self.current_threads = []
        self.stepping_mode = False
        self.loop = None
        self.thread = None
        self.disasm = Cs(CS_ARCH_X86, CS_MODE_64)
        self.error_log = []
        self.klog_thread = None
        self.klog_socket = None
        self.klog_active = False
        self.rpc_stub = None
        self.ps4_ip = None

    def start_async_loop(self):
        """Start async event loop in separate thread"""
        if self.loop is None:
            self.loop = asyncio.new_event_loop()
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
    
    def _run_loop(self):
        """Run the async loop"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
    
    def run_async(self, coro):
        """Run async coroutine and return result"""
        if self.loop is None:
            self.start_async_loop()
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=30)
    
    async def connect_async(self, ip_address):
        """Connect to PS4"""
        try:
            self.ps4 = ps4debug.PS4Debug(ip_address)
            self.ps4_ip = ip_address  # Store the IP address
            self.log_error(f"Created PS4Debug instance for {ip_address}")

            self.processes = await self.ps4.get_processes()
            self.connected = True
            self.log_error(f"Successfully connected to PS4 at {ip_address}, found {len(self.processes)} processes")
            return True
        except Exception as e:
            self.connected = False
            raise e
    
    async def scan_memory_async(self, pid, value, data_type='float', tolerance=0.1):
        """Scan memory for value"""
        results = []
        maps = await self.ps4.get_process_maps(pid)
        
        # Filter writable memory
        searchable_maps = [m for m in maps if m.prot & 0x2]
        
        for memory_map in searchable_maps:
            chunk_size = 0x100000  # 1MB chunks
            start_addr = memory_map.start
            end_addr = memory_map.end
            
            for addr in range(start_addr, end_addr, chunk_size):
                read_size = min(chunk_size, end_addr - addr)
                
                try:
                    data = await self.ps4.read_memory(pid, addr, read_size)
                    
                    if data_type == 'float':
                        for offset in range(0, len(data) - 4, 4):
                            try:
                                val = struct.unpack('<f', data[offset:offset+4])[0]
                                if abs(val - value) <= tolerance:
                                    results.append({
                                        'address': hex(addr + offset),
                                        'value': val,
                                        'type': 'float'
                                    })
                            except:
                                continue
                    
                    elif data_type == 'int32':
                        for offset in range(0, len(data) - 4, 4):
                            try:
                                val = struct.unpack('<i', data[offset:offset+4])[0]
                                if val == int(value):
                                    results.append({
                                        'address': hex(addr + offset),
                                        'value': val,
                                        'type': 'int32'
                                    })
                            except:
                                continue
                    
                    elif data_type == 'double':
                        for offset in range(0, len(data) - 8, 8):
                            try:
                                val = struct.unpack('<d', data[offset:offset+8])[0]
                                if abs(val - value) <= tolerance:
                                    results.append({
                                        'address': hex(addr + offset),
                                        'value': val,
                                        'type': 'double'
                                    })
                            except:
                                continue
                    
                    elif data_type == 'string':
                        # Search for string in memory
                        search_bytes = value.encode('utf-8')
                        search_len = len(search_bytes)
                        
                        for offset in range(0, len(data) - search_len + 1):
                            if data[offset:offset + search_len] == search_bytes:
                                # Found the string, extract it with context
                                end_offset = offset + search_len
                                # Look for null terminator
                                while end_offset < len(data) and data[end_offset] != 0:
                                    end_offset += 1
                                
                                found_str = data[offset:end_offset].decode('utf-8', errors='ignore')
                                results.append({
                                    'address': hex(addr + offset),
                                    'value': found_str[:100],  # Limit display length
                                    'type': 'string',
                                    'length': len(found_str)
                                })
                    
                    elif data_type == 'bytes':
                        # Search for byte pattern in memory
                        # Parse hex string like "DE AD BE EF" or "DEADBEEF"
                        hex_str = value.replace(' ', '').replace(',', '')
                        try:
                            search_bytes = bytes.fromhex(hex_str)
                        except ValueError:
                            continue  # Invalid hex string
                        
                        search_len = len(search_bytes)
                        
                        for offset in range(0, len(data) - search_len + 1):
                            if data[offset:offset + search_len] == search_bytes:
                                # Found the byte pattern
                                # Display surrounding bytes for context
                                context_start = max(0, offset - 16)
                                context_end = min(len(data), offset + search_len + 16)
                                context_bytes = data[context_start:context_end]
                                
                                results.append({
                                    'address': hex(addr + offset),
                                    'value': search_bytes.hex(),
                                    'type': 'bytes',
                                    'context': context_bytes.hex(),
                                    'length': search_len
                                })
                    
                    # Limit results for performance
                    if len(results) > 1000:
                        break
                        
                except Exception:
                    continue
            
            if len(results) > 1000:
                break
        
        return results
    
    async def read_memory_async(self, pid, address, length):
        """Read raw memory"""
        return await self.ps4.read_memory(pid, address, length)
    
    async def write_memory_async(self, pid, address, data):
        """Write raw memory"""
        return await self.ps4.write_memory(pid, address, data)
    
    async def disassemble_async(self, pid, address, length):
        """Disassemble memory at address"""
        try:
            code = await self.ps4.read_memory(pid, address, length)
            instructions = []
            
            for inst in self.disasm.disasm(code, address):
                instructions.append({
                    'address': hex(inst.address),
                    'mnemonic': inst.mnemonic,
                    'op_str': inst.op_str,
                    'bytes': inst.bytes.hex(),
                    'size': inst.size
                })
            
            return instructions
        except Exception as e:
            raise e

    def log_error(self, error_msg, exception=None):
        """Log error with timestamp"""
        import traceback
        timestamp = time.strftime('%H:%M:%S')
        if exception:
            tb = traceback.format_exc()
            full_msg = f"[{timestamp}] ERROR: {error_msg}\n{tb}"
        else:
            full_msg = f"[{timestamp}] ERROR: {error_msg}"

        self.error_log.append(full_msg)
        # Keep only last 50 errors
        if len(self.error_log) > 50:
            self.error_log = self.error_log[-50:]

        # Emit to websocket
        socketio.emit('error_log', {'message': full_msg})
        print(full_msg)

    def log_info(self, message):
        """Log info message"""
        timestamp = time.strftime('%H:%M:%S')
        full_msg = f"[{timestamp}] INFO: {message}"
        socketio.emit('log_info', {'message': message})
        print(full_msg)

    def log_warning(self, message):
        """Log warning message"""
        timestamp = time.strftime('%H:%M:%S')
        full_msg = f"[{timestamp}] WARNING: {message}"
        socketio.emit('log_warning', {'message': message})
        print(full_msg)

    def log_success(self, message):
        """Log success message"""
        timestamp = time.strftime('%H:%M:%S')
        full_msg = f"[{timestamp}] SUCCESS: {message}"
        socketio.emit('log_success', {'message': message})
        print(full_msg)  # Also print to console
        return full_msg

    async def start_debugger_async(self, pid, port=755):
        """Start debugger for process using async context manager"""
        try:
            # If debugger is already active, stop it first
            if self.debugger_active:
                self.log_info("Debugger already active, stopping existing session...")
                await self.stop_debugger_async()
                await asyncio.sleep(0.5)  # Give it time to clean up

            if not self.ps4:
                error_msg = 'Not connected to PS4'
                self.log_error(error_msg)
                return {'success': False, 'error': error_msg}

            self.log_info(f"Starting debugger for PID {pid} on port {port}")

            # Create a task that will manage the debugger context
            self.debugger_task = asyncio.create_task(self.run_debugger_context(pid, port))

            # Wait a bit for the debugger to initialize
            await asyncio.sleep(0.5)

            # Check if debugger started successfully
            if self.debugger_active and self.debugger:
                return {'success': True, 'threads': self.current_threads, 'message': f'Debugger started on PID {pid}'}
            else:
                return {'success': False, 'error': 'Failed to start debugger'}

        except Exception as e:
            self.debugger_active = False
            self.debugger = None
            error_msg = f"Failed to start debugger: {str(e)}"
            self.log_error(error_msg, e)
            return {'success': False, 'error': error_msg}

    async def run_debugger_context(self, pid, port):
        """Run the debugger context manager in a task"""
        try:
            # Use the async context manager pattern from the README
            async with self.ps4.debugger(pid, port=port, resume=True) as debugger:
                if debugger is None:
                    self.log_error("Failed to attach debugger - context returned None")
                    self.debugger_active = False
                    return

                self.debugger = debugger
                self.debugger_active = True
                self.log_success(f"Debugger attached successfully to PID {pid}")

                # Store debugger reference for breakpoint callbacks
                self.debugger = debugger
                self.log_info("Debugger context initialized")

                # Get thread list
                try:
                    self.current_threads = await debugger.get_threads()
                    self.log_info(f"Found {len(self.current_threads)} threads")
                except Exception as thread_error:
                    self.log_warning(f"Could not get thread list: {thread_error}")
                    self.current_threads = []

                # Keep the context alive until stopped
                while self.debugger_active:
                    await asyncio.sleep(1)

                self.log_info("Debugger context exiting")

        except Exception as e:
            error_msg = f"Debugger context error: {str(e)}"
            self.log_error(error_msg, e)
            self.debugger_active = False
            self.debugger = None

    async def check_port_755(self):
        """Check if port 755 is in use"""
        try:
            if not self.ps4:
                return False
            # Try to create a test socket to check if port is in use
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(0.5)
            result = test_sock.connect_ex((self.ps4.ip, 755))
            test_sock.close()
            return result == 0  # Port is in use if connection succeeds
        except Exception:
            return False

    async def get_ps4_info_async(self):
        """Get PS4 system information"""
        try:
            if not self.ps4 or not self.connected:
                return {'success': False, 'error': 'Not connected to PS4'}

            info = {}
            # Store the IP address from our connection
            if hasattr(self, 'ps4_ip'):
                info['ip'] = self.ps4_ip
            else:
                info['ip'] = 'Connected'

            # Get PS4Debug version
            try:
                version = await self.ps4.get_version()
                info['version'] = version
            except Exception as e:
                self.log_error(f"Failed to get version: {e}")
                info['version'] = 'Unknown'

            # Get kernel base address
            try:
                kernel_base = await self.ps4.get_kernel_base()
                info['kernel_base'] = kernel_base
            except Exception as e:
                self.log_error(f"Failed to get kernel base: {e}")
                info['kernel_base'] = None

            # Try to get console info (raw)
            try:
                # Call get_console_info and try to read the response
                response = await self.ps4.get_console_info()

                # The response is just a status code, but we can try to get more info
                # by checking what data might be available
                console_info_text = f"Response Code: {response}\n"

                # Add any additional system info we can gather
                console_info_text += f"PS4Debug Connected: Yes\n"
                console_info_text += f"IP Address: {self.ps4_ip if hasattr(self, 'ps4_ip') else 'Unknown'}\n"

                # Try to get process list info
                if self.processes:
                    console_info_text += f"Total Processes: {len(self.processes)}\n"
                    console_info_text += f"Available Processes:\n"
                    for p in self.processes[:10]:  # Show first 10 processes
                        console_info_text += f"  - {p['name']} (PID: {p['pid']})\n"
                    if len(self.processes) > 10:
                        console_info_text += f"  ... and {len(self.processes) - 10} more\n"

                info['console_info'] = console_info_text
            except Exception as e:
                self.log_error(f"Failed to get console info: {e}")
                info['console_info'] = f"Console info unavailable: {str(e)}"

            # Get current process info if available
            if self.current_pid:
                try:
                    # Find process name from our process list
                    process_name = 'Unknown'
                    for p in self.processes:
                        if p['pid'] == self.current_pid:
                            process_name = p['name']
                            break
                    info['process_info'] = f"{process_name} (PID: {self.current_pid})"
                except Exception:
                    info['process_info'] = f"PID: {self.current_pid}"
            else:
                info['process_info'] = None

            return {'success': True, **info}

        except Exception as e:
            self.log_error(f"Error getting PS4 info: {e}")
            return {'success': False, 'error': str(e)}

    async def get_debugger_status_async(self):
        """Get current debugger status"""
        try:
            port_in_use = await self.check_port_755()

            # If debugger is marked as active and port is in use, it's running
            if self.debugger_active and self.debugger:
                return {
                    'success': True,
                    'active': True,
                    'pid': self.current_pid,
                    'port_in_use': port_in_use,
                    'breakpoints': list(self.breakpoints.keys()),
                    'threads': self.current_threads
                }

            # If port is in use but debugger not marked active, we might have a stale session
            elif port_in_use and self.ps4 and self.connected:
                # Try to reconnect to existing debugger session
                if self.current_pid:
                    self.log_info(f"Port 755 in use, attempting to reconnect to PID {self.current_pid}")
                    # Attempt to reconnect
                    result = await self.start_debugger_async(self.current_pid, 755)
                    if result['success']:
                        return {
                            'success': True,
                            'active': True,
                            'pid': self.current_pid,
                            'port_in_use': True,
                            'reconnected': True,
                            'breakpoints': list(self.breakpoints.keys()),
                            'threads': self.current_threads
                        }

                return {
                    'success': True,
                    'active': False,
                    'port_in_use': True,
                    'message': 'Port 755 is in use but debugger not attached'
                }

            # Debugger not active
            return {
                'success': True,
                'active': False,
                'port_in_use': port_in_use
            }

        except Exception as e:
            self.log_error(f"Error checking debugger status: {e}")
            return {'success': False, 'error': str(e)}

    async def stop_debugger_async(self):
        """Stop debugger"""
        try:
            if self.debugger_active:
                self.log_info("Stopping debugger...")

                # Signal the debugger context to stop
                self.debugger_active = False

                # Cancel the debugger task if it exists
                if hasattr(self, 'debugger_task') and self.debugger_task:
                    self.debugger_task.cancel()
                    try:
                        await self.debugger_task
                    except asyncio.CancelledError:
                        pass

                # Clean up
                self.debugger = None
                self.debugger_task = None
                self.breakpoints = {}
                self.breakpoint_hits = []
                self.log_success("Debugger stopped successfully")
                return {'success': True}
            return {'success': False, 'error': 'No active debugger'}
        except Exception as e:
            error_msg = f"Failed to stop debugger: {str(e)}"
            self.log_error(error_msg, e)
            # Clean up anyway
            self.debugger = None
            self.debugger_task = None
            self.debugger_active = False
            return {'success': False, 'error': error_msg}

    async def set_breakpoint_async(self, address, enabled=True):
        """Set a breakpoint at address"""
        try:
            if not self.debugger_active or not self.debugger:
                return {'success': False, 'error': 'Debugger not active'}

            # Find next available breakpoint index (0-9)
            used_indices = {bp['id'] for bp in self.breakpoints.values()}
            bp_id = None
            for i in range(10):
                if i not in used_indices:
                    bp_id = i
                    break

            if bp_id is None:
                return {'success': False, 'error': 'Maximum breakpoints reached (10)'}

            # Create callback for this breakpoint
            async def callback(event):
                thread_id = event.interrupt.lwpid
                registers = event.interrupt.regs

                hit_info = {
                    'timestamp': time.time(),
                    'address': hex(registers.rip),
                    'thread_id': thread_id,
                    'breakpoint_index': bp_id,
                    'registers': {
                        'rax': hex(registers.rax),
                        'rbx': hex(registers.rbx),
                        'rcx': hex(registers.rcx),
                        'rdx': hex(registers.rdx),
                        'rsi': hex(registers.rsi),
                        'rdi': hex(registers.rdi),
                        'rbp': hex(registers.rbp),
                        'rsp': hex(registers.rsp),
                        'rip': hex(registers.rip),
                        'r8': hex(registers.r8),
                        'r9': hex(registers.r9),
                        'r10': hex(registers.r10),
                        'r11': hex(registers.r11),
                        'r12': hex(registers.r12),
                        'r13': hex(registers.r13),
                        'r14': hex(registers.r14),
                        'r15': hex(registers.r15),
                        'rflags': hex(registers.rflags),
                    }
                }
                self.breakpoint_hits.append(hit_info)

                # Update hit count
                if bp_id in self.breakpoints:
                    self.breakpoints[bp_id]['hit_count'] += 1

                # Emit via WebSocket
                socketio.emit('breakpoint_hit', hit_info)

                # Log the breakpoint hit
                self.log_info(f"Breakpoint {bp_id} hit at {hex(registers.rip)}")

            # Set the breakpoint with callback
            await self.debugger.set_breakpoint(bp_id, enabled, address, on_hit=callback)

            self.breakpoints[bp_id] = {
                'id': bp_id,
                'address': hex(address),
                'enabled': enabled,
                'hit_count': 0
            }

            self.log_success(f"Breakpoint {bp_id} set at {hex(address)}")
            return {'success': True, 'breakpoint': self.breakpoints[bp_id]}

        except Exception as e:
            error_msg = f"Failed to set breakpoint: {str(e)}"
            self.log_error(error_msg)
            return {'success': False, 'error': error_msg}

    async def remove_breakpoint_async(self, bp_id):
        """Remove a breakpoint"""
        try:
            if not self.debugger_active or not self.debugger:
                return {'success': False, 'error': 'Debugger not active'}

            if bp_id in self.breakpoints:
                # Disable the breakpoint by setting enabled=False
                address = int(self.breakpoints[bp_id]['address'], 16)
                await self.debugger.set_breakpoint(bp_id, False, address, on_hit=None)

                del self.breakpoints[bp_id]
                self.log_info(f"Breakpoint {bp_id} removed")
                return {'success': True}

            return {'success': False, 'error': 'Breakpoint not found'}
        except Exception as e:
            error_msg = f"Failed to remove breakpoint: {str(e)}"
            self.log_error(error_msg)
            return {'success': False, 'error': error_msg}

    async def step_instruction_async(self, thread_id=None):
        """Single step instruction"""
        try:
            if not self.debugger_active or not self.debugger:
                return {'success': False, 'error': 'Debugger not active'}

            # Perform single step
            self.stepping_mode = True
            await self.debugger.single_step()

            # Get updated registers from first thread if no thread specified
            if thread_id is None:
                threads = await self.debugger.get_threads()
                if threads:
                    thread_id = threads[0]

            if thread_id:
                regs = await self.debugger.get_registers(thread_id)
                return {
                    'success': True,
                    'registers': {
                        'rax': hex(regs.rax),
                        'rbx': hex(regs.rbx),
                        'rcx': hex(regs.rcx),
                        'rdx': hex(regs.rdx),
                        'rsi': hex(regs.rsi),
                        'rdi': hex(regs.rdi),
                        'rbp': hex(regs.rbp),
                        'rsp': hex(regs.rsp),
                        'rip': hex(regs.rip),
                        'r8': hex(regs.r8),
                        'r9': hex(regs.r9),
                        'r10': hex(regs.r10),
                        'r11': hex(regs.r11),
                        'r12': hex(regs.r12),
                        'r13': hex(regs.r13),
                        'r14': hex(regs.r14),
                        'r15': hex(regs.r15),
                        'rflags': hex(regs.rflags),
                    }
                }
            else:
                return {'success': True, 'message': 'Stepped successfully'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def continue_execution_async(self, thread_id=None):
        """Continue execution"""
        try:
            if not self.debugger_active or not self.debugger:
                return {'success': False, 'error': 'Debugger not active'}

            # Resume the process
            self.stepping_mode = False

            if thread_id:
                await self.debugger.resume_thread(thread_id)
            else:
                await self.debugger.resume_process()

            self.log_info("Execution resumed")
            return {'success': True, 'message': 'Execution resumed'}

        except Exception as e:
            error_msg = f"Failed to resume execution: {str(e)}"
            self.log_error(error_msg)
            return {'success': False, 'error': error_msg}

    def get_payloads(self):
        """Get list of available payloads"""
        payloads_dir = os.path.join(os.path.dirname(__file__), 'payloads')
        if not os.path.exists(payloads_dir):
            os.makedirs(payloads_dir)

        payloads = []
        try:
            for filename in os.listdir(payloads_dir):
                filepath = os.path.join(payloads_dir, filename)
                if os.path.isfile(filepath):
                    size = os.path.getsize(filepath)
                    payloads.append({
                        'name': filename,
                        'size': size,
                        'size_str': self.format_size(size)
                    })
        except Exception as e:
            self.log_error(f"Error listing payloads: {e}")

        return sorted(payloads, key=lambda x: x['name'].lower())

    def format_size(self, bytes):
        """Format bytes to human readable size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024.0:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.2f} TB"

    async def send_payload_async(self, ip_address, port, payload_name):
        """Send a payload to the PS4"""
        try:
            payloads_dir = os.path.join(os.path.dirname(__file__), 'payloads')
            payload_path = os.path.join(payloads_dir, payload_name)

            if not os.path.exists(payload_path):
                error_msg = f"Payload not found: {payload_name}"
                self.log_error(error_msg)
                return {'success': False, 'error': error_msg}

            # Read the payload
            with open(payload_path, 'rb') as f:
                payload_data = f.read()

            self.log_error(f"Sending payload {payload_name} ({len(payload_data)} bytes) to {ip_address}:{port}")

            # Create socket and send payload (like nc does)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            try:
                sock.connect((ip_address, port))
                sock.sendall(payload_data)
                self.log_error(f"Successfully sent {payload_name} to {ip_address}:{port}")
                result = {'success': True, 'message': f'Payload {payload_name} sent successfully'}
            except socket.timeout:
                error_msg = f"Timeout connecting to {ip_address}:{port}"
                self.log_error(error_msg)
                result = {'success': False, 'error': error_msg}
            except socket.error as e:
                error_msg = f"Socket error: {e}"
                self.log_error(error_msg)
                result = {'success': False, 'error': error_msg}
            finally:
                sock.close()

            return result

        except Exception as e:
            error_msg = f"Failed to send payload: {str(e)}"
            self.log_error(error_msg, e)
            return {'success': False, 'error': error_msg}

    def ftp_connect(self, ip_address, port=2121, username='anonymous', password=''):
        """Connect to FTP server"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip_address, port, timeout=10)
            ftp.login(username, password)
            return ftp
        except Exception as e:
            self.log_error(f"FTP connection failed: {e}")
            raise

    def ftp_list_directory(self, ftp, path='/'):
        """List FTP directory contents"""
        try:
            ftp.cwd(path)
            items = []

            # Use MLSD if available for better file info
            try:
                for name, facts in ftp.mlsd():
                    if name in ['.', '..']:
                        continue
                    items.append({
                        'name': name,
                        'type': 'dir' if facts.get('type') == 'dir' else 'file',
                        'size': int(facts.get('size', 0)),
                        'modified': facts.get('modify', '')
                    })
            except:
                # Fallback to LIST command
                raw_list = []
                ftp.retrlines('LIST', raw_list.append)

                for line in raw_list:
                    parts = line.split(None, 8)
                    if len(parts) >= 9:
                        name = parts[8]
                        is_dir = line[0] == 'd'
                        size = int(parts[4]) if not is_dir else 0
                        items.append({
                            'name': name,
                            'type': 'dir' if is_dir else 'file',
                            'size': size,
                            'modified': f"{parts[5]} {parts[6]} {parts[7]}"
                        })

            return {
                'path': ftp.pwd(),
                'items': sorted(items, key=lambda x: (x['type'] != 'dir', x['name'].lower()))
            }
        except Exception as e:
            self.log_error(f"Failed to list FTP directory: {e}")
            raise

    def ftp_download_file(self, ftp, remote_path):
        """Download file from FTP"""
        try:
            buffer = BytesIO()
            ftp.retrbinary(f'RETR {remote_path}', buffer.write)
            buffer.seek(0)
            return buffer
        except Exception as e:
            self.log_error(f"Failed to download FTP file: {e}")
            raise

    def ftp_upload_file(self, ftp, remote_path, file_data):
        """Upload file to FTP"""
        try:
            buffer = BytesIO(file_data)
            ftp.storbinary(f'STOR {remote_path}', buffer)
            return True
        except Exception as e:
            self.log_error(f"Failed to upload FTP file: {e}")
            raise

    def ftp_delete_file(self, ftp, remote_path):
        """Delete file from FTP"""
        try:
            ftp.delete(remote_path)
            return True
        except Exception as e:
            self.log_error(f"Failed to delete FTP file: {e}")
            raise

    def ftp_create_directory(self, ftp, path):
        """Create directory on FTP"""
        try:
            ftp.mkd(path)
            return True
        except Exception as e:
            self.log_error(f"Failed to create FTP directory: {e}")
            raise

    def ftp_delete_directory(self, ftp, path):
        """Delete directory from FTP"""
        try:
            ftp.rmd(path)
            return True
        except Exception as e:
            self.log_error(f"Failed to delete FTP directory: {e}")
            raise

    def start_klog_reader(self, ip_address, port=3232):
        """Start reading kernel log from PS4"""
        if self.klog_active:
            return {'success': False, 'error': 'Klog reader already active'}

        def klog_reader_thread():
            try:
                self.klog_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.klog_socket.settimeout(5)  # 5 second timeout for connection
                self.klog_socket.connect((ip_address, port))
                self.klog_socket.settimeout(0.1)  # Short timeout for reads
                self.klog_active = True

                socketio.emit('klog_status', {'connected': True, 'ip': ip_address, 'port': port})

                buffer = ""
                while self.klog_active:
                    try:
                        data = self.klog_socket.recv(4096)
                        if not data:
                            break

                        # Decode and handle partial lines
                        text = data.decode('utf-8', errors='replace')
                        buffer += text

                        # Split by newlines and emit complete lines
                        lines = buffer.split('\n')
                        buffer = lines[-1]  # Keep last incomplete line in buffer

                        for line in lines[:-1]:
                            if line.strip():
                                socketio.emit('klog_line', {
                                    'line': line,
                                    'timestamp': time.time()
                                })
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.klog_active:
                            self.log_error(f"Klog read error: {e}")
                        break

            except socket.timeout:
                error_msg = f"Timeout connecting to klog at {ip_address}:{port}"
                self.log_error(error_msg)
                socketio.emit('klog_error', {'error': error_msg})
            except Exception as e:
                error_msg = f"Failed to connect to klog: {e}"
                self.log_error(error_msg)
                socketio.emit('klog_error', {'error': error_msg})
            finally:
                self.klog_active = False
                if self.klog_socket:
                    try:
                        self.klog_socket.close()
                    except:
                        pass
                    self.klog_socket = None
                socketio.emit('klog_status', {'connected': False})

        self.klog_thread = threading.Thread(target=klog_reader_thread, daemon=True)
        self.klog_thread.start()
        return {'success': True, 'message': f'Connecting to klog at {ip_address}:{port}'}

    async def call_function_async(self, address, params, param_format='', output_format='Q'):
        """Call a function at an address with parameters"""
        try:
            self.log_info(f"call_function_async: address={hex(address)}, params={params}, param_format={param_format}, output_format={output_format}")

            if not self.ps4 or not self.current_pid:
                error_msg = 'Not connected or no process selected'
                self.log_error(f"call_function_async: {error_msg}")
                return {'success': False, 'error': error_msg}

            # Install RPC stub if not already installed
            if not hasattr(self, 'rpc_stub') or self.rpc_stub is None:
                self.log_info("Installing RPC stub...")
                self.rpc_stub = await self.ps4.install_rpc(self.current_pid)
                if self.rpc_stub:
                    self.log_success(f"RPC stub installed at {hex(self.rpc_stub)}")
                else:
                    self.log_error("Failed to install RPC stub")
                    return {'success': False, 'error': 'Failed to install RPC stub'}

            # Parse parameters based on format
            if param_format:
                # User specified format
                self.log_info(f"Using specified param format: {param_format}")
                result = await self.ps4.call(self.current_pid, address, *params,
                                            parameter_format=param_format,
                                            output_format=output_format,
                                            rpc_stub=self.rpc_stub)
            else:
                # Auto-detect format based on parameters (up to 6 integers)
                int_params = []
                for p in params[:6]:  # Maximum 6 parameters
                    try:
                        if '.' in str(p):
                            int_params.append(float(p))
                        else:
                            int_params.append(int(p, 16) if isinstance(p, str) and p.startswith('0x') else int(p))
                    except Exception as parse_error:
                        self.log_warning(f"Failed to parse parameter {p}: {parse_error}, using 0")
                        int_params.append(0)

                self.log_info(f"Parsed parameters: {int_params}")
                result = await self.ps4.call(self.current_pid, address, *int_params,
                                            rpc_stub=self.rpc_stub)

            # Result is always a tuple, even for single values
            if isinstance(result, tuple) and len(result) == 1:
                result_value = result[0]
            else:
                result_value = result

            self.log_success(f"Function called at {hex(address)}, returned: {hex(result_value) if isinstance(result_value, int) else result_value}")
            return {
                'success': True,
                'address': hex(address),
                'return_value': result_value,
                'return_hex': hex(result_value) if isinstance(result_value, int) else None
            }

        except Exception as e:
            error_msg = f"Failed to call function: {str(e)}"
            self.log_error(error_msg, e)
            return {'success': False, 'error': error_msg}

    async def allocate_memory_async(self, size):
        """Allocate memory in the process"""
        try:
            if not self.ps4 or not self.current_pid:
                return {'success': False, 'error': 'Not connected or no process selected'}

            # Round up to page size (4096)
            size = ((size + 4095) // 4096) * 4096

            address = await self.ps4.allocate_memory(self.current_pid, size)

            self.log_success(f"Allocated {size} bytes at {hex(address)}")
            return {
                'success': True,
                'address': hex(address),
                'size': size
            }

        except Exception as e:
            error_msg = f"Failed to allocate memory: {str(e)}"
            self.log_error(error_msg)
            return {'success': False, 'error': error_msg}

    async def free_memory_async(self, address, size):
        """Free allocated memory"""
        try:
            if not self.ps4 or not self.current_pid:
                return {'success': False, 'error': 'Not connected or no process selected'}

            await self.ps4.free_memory(self.current_pid, address, size)

            self.log_success(f"Freed {size} bytes at {hex(address)}")
            return {
                'success': True,
                'address': hex(address),
                'size': size
            }

        except Exception as e:
            error_msg = f"Failed to free memory: {str(e)}"
            self.log_error(error_msg)
            return {'success': False, 'error': error_msg}

    async def inject_assembly_async(self, assembly_hex, params, param_format='', output_format='Q'):
        """Inject and execute assembly code"""
        try:
            if not self.ps4 or not self.current_pid:
                return {'success': False, 'error': 'Not connected or no process selected'}

            # Convert hex string to bytes
            assembly = bytes.fromhex(assembly_hex.replace(' ', '').replace('0x', ''))

            # Use memory context for injection
            async with self.ps4.memory(self.current_pid, len(assembly) + 4096) as memory:
                # Write assembly to allocated memory
                await memory.write(assembly)

                self.log_info(f"Injected {len(assembly)} bytes of assembly at {hex(memory.address)}")

                # Execute the code
                if params:
                    if param_format:
                        result = await memory.call(*params, parameter_format=param_format, output_format=output_format)
                    else:
                        int_params = []
                        for p in params[:6]:
                            try:
                                if '.' in str(p):
                                    int_params.append(float(p))
                                else:
                                    int_params.append(int(p, 16) if isinstance(p, str) and p.startswith('0x') else int(p))
                            except:
                                int_params.append(0)
                        result = await memory.call(*int_params)
                else:
                    result = await memory.call()

                self.log_success(f"Assembly executed, returned: {hex(result) if isinstance(result, int) else result}")

                return {
                    'success': True,
                    'address': hex(memory.address),
                    'size': len(assembly),
                    'return_value': result,
                    'return_hex': hex(result) if isinstance(result, int) else None
                }

        except Exception as e:
            error_msg = f"Failed to inject assembly: {str(e)}"
            self.log_error(error_msg)
            return {'success': False, 'error': error_msg}

    def stop_klog_reader(self):
        """Stop reading kernel log"""
        if not self.klog_active:
            return {'success': False, 'error': 'Klog reader not active'}

        self.klog_active = False

        # Close socket to interrupt read
        if self.klog_socket:
            try:
                self.klog_socket.close()
            except:
                pass
            self.klog_socket = None

        # Wait for thread to finish (with timeout)
        if self.klog_thread:
            self.klog_thread.join(timeout=2)
            self.klog_thread = None

        return {'success': True, 'message': 'Klog reader stopped'}

# Global manager instance
manager = PS4Manager()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/connect', methods=['POST'])
def connect():
    """Connect to PS4"""
    try:
        data = request.json
        ip_address = data.get('ip_address')
        
        if not ip_address:
            # Try auto-discovery
            ip_address = ps4debug.PS4Debug.find_ps4()
            if not ip_address:
                return jsonify({'success': False, 'error': 'PS4 not found on network'})
        
        manager.run_async(manager.connect_async(ip_address))
        
        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'processes': [{'name': p.name, 'pid': p.pid} for p in manager.processes[:50]]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/processes')
def get_processes():
    """Get process list - refresh from PS4"""
    if not manager.connected:
        return jsonify({'success': False, 'error': 'Not connected'})

    try:
        # Refresh the process list from PS4
        processes = manager.run_async(manager.ps4.get_processes())
        manager.processes = processes

        return jsonify({
            'success': True,
            'processes': [{'name': p.name, 'pid': p.pid} for p in processes]
        })
    except Exception as e:
        manager.log_error(f"Failed to refresh process list: {str(e)}")
        # Return cached list if refresh fails
        return jsonify({
            'success': True,
            'processes': [{'name': p.name, 'pid': p.pid} for p in manager.processes],
            'warning': 'Using cached process list'
        })

@app.route('/api/select_process', methods=['POST'])
def select_process():
    """Select active process"""
    data = request.json
    pid = data.get('pid')
    
    if not manager.connected:
        return jsonify({'success': False, 'error': 'Not connected'})
    
    manager.current_pid = pid
    return jsonify({'success': True, 'pid': pid})

@app.route('/api/scan', methods=['POST'])
def scan_memory():
    """Scan memory for value"""
    if not manager.connected or not manager.current_pid:
        return jsonify({'success': False, 'error': 'Not connected or no process selected'})
    
    data = request.json
    data_type = data.get('type', 'float')
    
    # Handle different value types
    if data_type == 'string':
        value = data.get('value', '')
        tolerance = 0  # Not used for strings
    elif data_type == 'bytes':
        value = data.get('value', '')  # Hex string
        tolerance = 0  # Not used for bytes
    else:
        value = float(data.get('value', 0))
        tolerance = float(data.get('tolerance', 0.1))
    
    try:
        results = manager.run_async(
            manager.scan_memory_async(manager.current_pid, value, data_type, tolerance)
        )
        
        # Store results for filtering
        scan_id = str(time.time())
        manager.scan_results[scan_id] = results
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'count': len(results),
            'results': results[:100]  # Return first 100
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/filter_scan', methods=['POST'])
def filter_scan():
    """Filter previous scan results"""
    if not manager.connected or not manager.current_pid:
        return jsonify({'success': False, 'error': 'Not connected or no process selected'})
    
    data = request.json
    scan_id = data.get('scan_id')
    new_value = float(data.get('value', 0))
    tolerance = float(data.get('tolerance', 0.1))
    
    if scan_id not in manager.scan_results:
        return jsonify({'success': False, 'error': 'Invalid scan ID'})
    
    previous_results = manager.scan_results[scan_id]
    filtered = []
    
    for result in previous_results:
        try:
            addr = int(result['address'], 16)
            
            if result['type'] == 'float':
                current = manager.run_async(
                    manager.ps4.read_float(manager.current_pid, addr)
                )
            elif result['type'] == 'int32':
                current = manager.run_async(
                    manager.ps4.read_int32(manager.current_pid, addr)
                )
            elif result['type'] == 'double':
                current = manager.run_async(
                    manager.ps4.read_double(manager.current_pid, addr)
                )
            
            if abs(current - new_value) <= tolerance:
                filtered.append({
                    'address': result['address'],
                    'value': current,
                    'type': result['type'],
                    'old_value': result['value']
                })
        except:
            continue
    
    # Update stored results
    manager.scan_results[scan_id] = filtered
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'count': len(filtered),
        'results': filtered[:100]
    })

@app.route('/api/read', methods=['POST'])
def read_memory():
    """Read memory at address"""
    if not manager.connected or not manager.current_pid:
        return jsonify({'success': False, 'error': 'Not connected or no process selected'})
    
    data = request.json
    address = int(data.get('address', '0'), 16)
    length = int(data.get('length', 256))
    format_type = data.get('format', 'hex')
    
    try:
        raw_data = manager.run_async(
            manager.read_memory_async(manager.current_pid, address, length)
        )
        
        result = {
            'success': True,
            'address': hex(address),
            'length': length
        }
        
        if format_type == 'hex':
            # Format as hex dump
            hex_lines = []
            for i in range(0, len(raw_data), 16):
                chunk = raw_data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                hex_lines.append(f'{address+i:08x}: {hex_part:<48} {ascii_part}')
            result['data'] = '\n'.join(hex_lines)
            
        elif format_type == 'raw':
            result['data'] = raw_data.hex()
            
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/write', methods=['POST'])
def write_memory():
    """Write memory at address"""
    if not manager.connected or not manager.current_pid:
        return jsonify({'success': False, 'error': 'Not connected or no process selected'})
    
    data = request.json
    address = int(data.get('address', '0'), 16)
    value = data.get('value')
    data_type = data.get('type', 'int32')
    
    try:
        if data_type == 'int32':
            status = manager.run_async(
                manager.ps4.write_int32(manager.current_pid, address, int(value))
            )
        elif data_type == 'float':
            status = manager.run_async(
                manager.ps4.write_float(manager.current_pid, address, float(value))
            )
        elif data_type == 'double':
            status = manager.run_async(
                manager.ps4.write_double(manager.current_pid, address, float(value))
            )
        elif data_type == 'bytes':
            byte_data = bytes.fromhex(value)
            status = manager.run_async(
                manager.write_memory_async(manager.current_pid, address, byte_data)
            )
        else:
            return jsonify({'success': False, 'error': 'Invalid data type'})
        
        return jsonify({'success': True, 'address': hex(address)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/disassemble', methods=['POST'])
def disassemble():
    """Disassemble code at address"""
    if not manager.connected or not manager.current_pid:
        return jsonify({'success': False, 'error': 'Not connected or no process selected'})
    
    data = request.json
    address = int(data.get('address', '0'), 16)
    length = int(data.get('length', 100))
    
    try:
        instructions = manager.run_async(
            manager.disassemble_async(manager.current_pid, address, length)
        )
        
        return jsonify({
            'success': True,
            'address': hex(address),
            'instructions': instructions
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/hex_viewer', methods=['POST'])
def hex_viewer():
    """Continuous hex viewer for memory range"""
    if not manager.connected or not manager.current_pid:
        return jsonify({'success': False, 'error': 'Not connected or no process selected'})
    
    data = request.json
    start_address = int(data.get('start_address', '0'), 16)
    length = int(data.get('length', 256))
    
    # Limit length for safety
    if length > 0x10000:  # 64KB max
        length = 0x10000
    
    try:
        raw_data = manager.run_async(
            manager.read_memory_async(manager.current_pid, start_address, length)
        )
        
        # Format as hex dump with ASCII
        hex_lines = []
        ascii_lines = []
        
        for i in range(0, len(raw_data), 16):
            chunk = raw_data[i:i+16]
            
            # Hex part
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            # Pad if less than 16 bytes
            if len(chunk) < 16:
                hex_part += '   ' * (16 - len(chunk))
            
            # ASCII part
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            
            hex_lines.append({
                'offset': f'{start_address + i:08x}',
                'hex': hex_part,
                'ascii': ascii_part,
                'raw': chunk.hex()
            })
        
        return jsonify({
            'success': True,
            'start_address': hex(start_address),
            'length': length,
            'lines': hex_lines,
            'timestamp': time.time()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/debugger/start', methods=['POST'])
def start_debugger():
    """Start debugger for current process"""
    if not manager.connected or not manager.current_pid:
        return jsonify({'success': False, 'error': 'Not connected or no process selected'})

    result = manager.run_async(
        manager.start_debugger_async(manager.current_pid)
    )
    return jsonify(result)

@app.route('/api/debugger/error_log', methods=['GET'])
def get_error_log():
    """Get the error log"""
    return jsonify({
        'success': True,
        'log': manager.error_log,
        'count': len(manager.error_log)
    })

@app.route('/api/ps4/info', methods=['GET'])
def get_ps4_info():
    """Get PS4 system information"""
    result = manager.run_async(manager.get_ps4_info_async())
    return jsonify(result)

@app.route('/api/debugger/status', methods=['GET'])
def get_debugger_status():
    """Get debugger status"""
    result = manager.run_async(manager.get_debugger_status_async())
    return jsonify(result)

@app.route('/api/debugger/stop', methods=['POST'])
def stop_debugger():
    """Stop debugger"""
    result = manager.run_async(manager.stop_debugger_async())
    return jsonify(result)

@app.route('/api/debugger/breakpoint', methods=['POST'])
def set_breakpoint():
    """Set a breakpoint"""
    data = request.json
    address = int(data.get('address', '0'), 16)
    enabled = data.get('enabled', True)

    result = manager.run_async(
        manager.set_breakpoint_async(address, enabled)
    )
    return jsonify(result)

@app.route('/api/debugger/breakpoint/<int:bp_id>', methods=['DELETE'])
def remove_breakpoint(bp_id):
    """Remove a breakpoint"""
    result = manager.run_async(
        manager.remove_breakpoint_async(bp_id)
    )
    return jsonify(result)

@app.route('/api/debugger/step', methods=['POST'])
def step_instruction():
    """Single step instruction"""
    data = request.json
    thread_id = data.get('thread_id', 0)

    result = manager.run_async(
        manager.step_instruction_async(thread_id)
    )
    return jsonify(result)

@app.route('/api/debugger/continue', methods=['POST'])
def continue_execution():
    """Continue execution"""
    data = request.json
    thread_id = data.get('thread_id', None)

    result = manager.run_async(
        manager.continue_execution_async(thread_id)
    )
    return jsonify(result)

@app.route('/api/debugger/breakpoints', methods=['GET'])
def list_breakpoints():
    """List all breakpoints"""
    return jsonify({
        'success': True,
        'breakpoints': list(manager.breakpoints.values()),
        'hits': manager.breakpoint_hits[-10:]  # Last 10 hits
    })

# Payload Sender Routes
@app.route('/api/payloads', methods=['GET'])
def get_payloads():
    """Get list of available payloads"""
    try:
        payloads = manager.get_payloads()
        return jsonify({'success': True, 'payloads': payloads})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/payload/send', methods=['POST'])
def send_payload():
    """Send a payload to PS4"""
    data = request.json
    ip_address = data.get('ip_address')
    port = data.get('port', 9090)
    payload_name = data.get('payload_name')

    if not all([ip_address, payload_name]):
        return jsonify({'success': False, 'error': 'Missing required parameters'})

    result = manager.run_async(
        manager.send_payload_async(ip_address, port, payload_name)
    )

    if result.get('success'):
        # Get file size for response
        payloads_dir = os.path.join(os.path.dirname(__file__), 'payloads')
        payload_path = os.path.join(payloads_dir, payload_name)
        bytes_sent = os.path.getsize(payload_path) if os.path.exists(payload_path) else 0
        result['bytes_sent'] = bytes_sent

    return jsonify(result)

# FTP Browser Routes
@app.route('/api/ftp/connect', methods=['POST'])
def ftp_connect():
    """Connect to FTP server"""
    data = request.json
    ip = data.get('ip', '192.168.0.106')
    port = data.get('port', 2121)

    try:
        # Store FTP connection in session
        ftp = manager.ftp_connect(ip, port)
        session['ftp_connected'] = True
        session['ftp_ip'] = ip
        session['ftp_port'] = port
        return jsonify({'success': True, 'message': f'Connected to FTP at {ip}:{port}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ftp/list', methods=['POST'])
def ftp_list():
    """List FTP directory contents"""
    data = request.json
    path = data.get('path', '/')
    ip = session.get('ftp_ip', data.get('ip', '192.168.0.106'))
    port = session.get('ftp_port', data.get('port', 2121))

    try:
        ftp = manager.ftp_connect(ip, port)
        result = manager.ftp_list_directory(ftp, path)
        ftp.quit()
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ftp/download', methods=['POST'])
def ftp_download():
    """Download file from FTP"""
    data = request.json
    remote_path = data.get('path')
    filename = os.path.basename(remote_path)
    ip = session.get('ftp_ip', data.get('ip', '192.168.0.106'))
    port = session.get('ftp_port', data.get('port', 2121))

    try:
        ftp = manager.ftp_connect(ip, port)
        file_buffer = manager.ftp_download_file(ftp, remote_path)
        ftp.quit()

        return send_file(
            file_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ftp/upload', methods=['POST'])
def ftp_upload():
    """Upload file to FTP"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})

    file = request.files['file']
    remote_path = request.form.get('path', '/')
    ip = session.get('ftp_ip', request.form.get('ip', '192.168.0.106'))
    port = int(session.get('ftp_port', request.form.get('port', 2121)))

    try:
        ftp = manager.ftp_connect(ip, port)
        full_path = os.path.join(remote_path, file.filename)
        manager.ftp_upload_file(ftp, full_path, file.read())
        ftp.quit()
        return jsonify({'success': True, 'message': f'Uploaded {file.filename}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ftp/delete', methods=['POST'])
def ftp_delete():
    """Delete file or directory from FTP"""
    data = request.json
    path = data.get('path')
    is_dir = data.get('is_dir', False)
    ip = session.get('ftp_ip', data.get('ip', '192.168.0.106'))
    port = session.get('ftp_port', data.get('port', 2121))

    try:
        ftp = manager.ftp_connect(ip, port)
        if is_dir:
            manager.ftp_delete_directory(ftp, path)
        else:
            manager.ftp_delete_file(ftp, path)
        ftp.quit()
        return jsonify({'success': True, 'message': f'Deleted {path}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ftp/mkdir', methods=['POST'])
def ftp_mkdir():
    """Create directory on FTP"""
    data = request.json
    path = data.get('path')
    ip = session.get('ftp_ip', data.get('ip', '192.168.0.106'))
    port = session.get('ftp_port', data.get('port', 2121))

    try:
        ftp = manager.ftp_connect(ip, port)
        manager.ftp_create_directory(ftp, path)
        ftp.quit()
        return jsonify({'success': True, 'message': f'Created directory {path}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Kernel Log Routes
@app.route('/api/klog/start', methods=['POST'])
def start_klog():
    """Start kernel log reader"""
    data = request.json
    ip = data.get('ip', '192.168.0.106')
    port = data.get('port', 3232)

    result = manager.start_klog_reader(ip, port)
    return jsonify(result)

@app.route('/api/klog/stop', methods=['POST'])
def stop_klog():
    """Stop kernel log reader"""
    result = manager.stop_klog_reader()
    return jsonify(result)

@app.route('/api/klog/status', methods=['GET'])
def klog_status():
    """Get klog reader status"""
    return jsonify({
        'active': manager.klog_active,
        'connected': manager.klog_socket is not None
    })

@app.route('/api/klog/export', methods=['POST'])
def export_klog():
    """Export kernel log to file"""
    try:
        data = request.json
        log_lines = data.get('lines', [])

        if not log_lines:
            return jsonify({'success': False, 'error': 'No log entries to export'})

        # Create filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'klog_{timestamp}.txt'
        filepath = os.path.join(os.path.dirname(__file__), 'logs', filename)

        # Ensure logs directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Write log lines to file
        with open(filepath, 'w') as f:
            for entry in log_lines:
                if isinstance(entry, dict):
                    ts = datetime.fromtimestamp(entry.get('timestamp', 0)).isoformat()
                    line = entry.get('line', '')
                    f.write(f"[{ts}] {line}\n")
                else:
                    f.write(f"{entry}\n")

        # Return success with file info
        return jsonify({
            'success': True,
            'filename': filename,
            'path': filepath,
            'lines': len(log_lines)
        })

    except Exception as e:
        manager.log_error(f"Failed to export klog: {e}")
        return jsonify({'success': False, 'error': str(e)})

@socketio.on('call_function')
def call_function(data):
    """Call a function at an address with parameters"""
    manager.log_info(f"RCE: call_function request received: {data}")

    if not manager.connected or not manager.current_pid:
        error_msg = 'Not connected or no process selected'
        manager.log_error(f"RCE: {error_msg}")
        emit('error', {'message': error_msg})
        return

    try:
        address = int(data.get('address', '0'), 16)
        params = data.get('parameters', [])
        param_format = data.get('parameter_format', '')
        output_format = data.get('output_format', 'Q')

        manager.log_info(f"RCE: Calling function at {hex(address)} with params: {params}")

        result = manager.run_async(
            manager.call_function_async(address, params, param_format, output_format)
        )

        manager.log_info(f"RCE: Function call result: {result}")
        emit('call_result', result)
    except Exception as e:
        error_msg = f'Failed to call function: {str(e)}'
        manager.log_error(f"RCE: {error_msg}", e)
        emit('error', {'message': error_msg})

@socketio.on('allocate_memory')
def allocate_memory(data):
    """Allocate memory in the process"""
    if not manager.connected or not manager.current_pid:
        emit('error', {'message': 'Not connected or no process selected'})
        return

    try:
        size = int(data.get('size', 4096))
        result = manager.run_async(manager.allocate_memory_async(size))
        emit('memory_allocated', result)
    except Exception as e:
        emit('error', {'message': f'Failed to allocate memory: {str(e)}'})

@socketio.on('free_memory')
def free_memory(data):
    """Free allocated memory"""
    if not manager.connected or not manager.current_pid:
        emit('error', {'message': 'Not connected or no process selected'})
        return

    try:
        address = int(data.get('address', '0'), 16)
        size = int(data.get('size', 4096))
        result = manager.run_async(manager.free_memory_async(address, size))
        emit('memory_freed', result)
    except Exception as e:
        emit('error', {'message': f'Failed to free memory: {str(e)}'})

@socketio.on('inject_assembly')
def inject_assembly(data):
    """Inject and execute assembly code"""
    if not manager.connected or not manager.current_pid:
        emit('error', {'message': 'Not connected or no process selected'})
        return

    try:
        assembly_hex = data.get('assembly', '')
        params = data.get('parameters', [])
        param_format = data.get('parameter_format', '')
        output_format = data.get('output_format', 'Q')

        result = manager.run_async(
            manager.inject_assembly_async(assembly_hex, params, param_format, output_format)
        )

        emit('injection_result', result)
    except Exception as e:
        emit('error', {'message': f'Failed to inject assembly: {str(e)}'})

@socketio.on('monitor_address')
def handle_monitor(data):
    """Monitor an address for changes"""
    if not manager.connected or not manager.current_pid:
        emit('error', {'message': 'Not connected'})
        return
    
    address = int(data.get('address', '0'), 16)
    data_type = data.get('type', 'float')
    interval = float(data.get('interval', 0.5))
    
    def monitor_loop():
        while True:
            try:
                if data_type == 'float':
                    value = manager.run_async(
                        manager.ps4.read_float(manager.current_pid, address)
                    )
                elif data_type == 'int32':
                    value = manager.run_async(
                        manager.ps4.read_int32(manager.current_pid, address)
                    )
                elif data_type == 'double':
                    value = manager.run_async(
                        manager.ps4.read_double(manager.current_pid, address)
                    )
                else:
                    break
                
                socketio.emit('monitor_update', {
                    'address': hex(address),
                    'value': value,
                    'type': data_type,
                    'timestamp': time.time()
                })
                
                time.sleep(interval)
            except:
                break
    
    # Start monitoring in background thread
    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()

def check_root_permissions():
    """Check if running as root and warn about debugger limitations"""
    if os.geteuid() != 0:
        print("\n" + "="*60)
        print("⚠️  WARNING: Not running as root!")
        print("="*60)
        print("The debugger functionality requires root permissions to")
        print("access port 755 for PS4 debugging operations.")
        print("\nYou can still use the application, but debugger features")
        print("will not work properly.")
        print("\nTo run with full functionality:")
        print("  sudo python app.py")
        print("="*60 + "\n")
        return False
    return True

def start_flask():
    """Start Flask server in a separate thread"""
    socketio.run(app, debug=False, host='0.0.0.0', port=5001, allow_unsafe_werkzeug=True)

def create_webview_window():
    """Create and show the webview window"""
    # Create a window with the Flask app
    window = webview.create_window(
        'PS4 Memory Debugger',
        'http://127.0.0.1:5001',
        width=1400,
        height=900,
        resizable=True,
        fullscreen=False
    )

    # Start webview (this blocks until window is closed)
    webview.start()

if __name__ == '__main__':
    # Check for root permissions
    is_root = check_root_permissions()

    # Start the async loop for PS4Manager
    manager.start_async_loop()

    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    # Give Flask time to start
    time.sleep(2)

    print(f"🚀 PS4 Memory Debugger started!")
    print(f"📍 Server running at: http://127.0.0.1:5001")

    if not is_root:
        print(f"⚠️  Running with limited functionality (no debugger access)")
    else:
        print(f"✅ Running with full functionality (root access)")

    # Check if we should skip webview (useful when running as root or if webview has issues)
    skip_webview = '--no-webview' in sys.argv or os.environ.get('NO_WEBVIEW', '').lower() in ('1', 'true', 'yes')

    if is_root and not skip_webview:
        print(f"ℹ️  Running as root - webview may not work with Qt")
        print(f"💡 Use --no-webview flag or set NO_WEBVIEW=1 to skip webview")
        skip_webview = True  # Auto-skip webview when root

    if not skip_webview:
        # Create and run the webview window
        try:
            create_webview_window()
        except KeyboardInterrupt:
            print("\n👋 Shutting down PS4 Memory Debugger...")
            sys.exit(0)
        except Exception as e:
            print(f"❌ Error creating webview window: {e}")
            print(f"💡 You can still access the application at: http://127.0.0.1:5001")
            skip_webview = True

    if skip_webview:
        print(f"\n📱 Access the application in your browser at:")
        print(f"   http://127.0.0.1:5001")
        print(f"   http://localhost:5001")
        print(f"\n   Press Ctrl+C to quit\n")

        # Keep the server running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n👋 Shutting down PS4 Memory Debugger...")
            sys.exit(0)
