import api from './api';
import type { Device } from '../types';

export interface TrustDeviceRequest {
  deviceId: string;
  durationDays?: number;
}

export interface UntrustDeviceRequest {
  deviceId: string;
}

export interface UpdateDeviceRequest {
  name: string;
}

export const deviceService = {
  /**
   * List all devices for the current user
   */
  async listDevices(): Promise<Device[]> {
    const response = await api.get<Device[]>('/devices');
    return response.data;
  },

  /**
   * Get a specific device by ID
   */
  async getDevice(deviceId: string): Promise<Device> {
    const response = await api.get<Device>(`/devices/${deviceId}`);
    return response.data;
  },

  /**
   * Get the current device
   */
  async getCurrentDevice(): Promise<Device> {
    const response = await api.get<Device>('/devices/current');
    return response.data;
  },

  /**
   * Trust a device
   */
  async trustDevice(req: TrustDeviceRequest): Promise<Device> {
    const response = await api.post<Device>('/devices/trust', req);
    return response.data;
  },

  /**
   * Untrust a device
   */
  async untrustDevice(req: UntrustDeviceRequest): Promise<Device> {
    const response = await api.post<Device>('/devices/untrust', req);
    return response.data;
  },

  /**
   * Rename a device
   */
  async updateDevice(deviceId: string, data: UpdateDeviceRequest): Promise<Device> {
    const response = await api.patch<Device>(`/devices/${deviceId}`, data);
    return response.data;
  },

  /**
   * Remove a device and revoke its session
   */
  async removeDevice(deviceId: string): Promise<void> {
    await api.delete(`/devices/${deviceId}`);
  },

  /**
   * Logout a device (end session but keep record)
   */
  async logoutDevice(deviceId: string): Promise<void> {
    await api.post(`/devices/${deviceId}/logout`);
  },

  /**
   * Revoke all other devices
   */
  async revokeAllOtherDevices(): Promise<void> {
    await api.post('/users/me/devices/revoke-all');
  },
};

export default deviceService;
