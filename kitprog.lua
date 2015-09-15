-- Cypress KitProg protocol dissector for Wireshark
--
-- Copyright (C) 2015 Forest Crossman <cyrozap@gmail.com>
--
-- Based on the SysClk LWLA protocol dissector for Wireshark,
-- Copyright (C) 2014 Daniel Elstner <daniel.kitta@gmail.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, see <http://www.gnu.org/licenses/>.

-- Usage: wireshark -X lua_script:kitprog.lua
--
-- It is not advisable to install this dissector globally, since
-- it will try to interpret the communication of any USB device
-- using the vendor-specific interface class.

-- Create custom protocol for the KitProg.
p_kitprog = Proto("kitprog", "Cypress Semiconductor Protocol for JTAG and SWD debuggers")

-- Control commands either read or write
local command_types = {
    [0x01] = "Read",
    [0x02] = "Write"
}

-- There is currently only a single known "Program" command
local commands = {
    [0x07] = "Program"
}

-- These are the subcommands (modes) of the "Program" command
local modes = {
    [0x01] = "Poll KitProg Status",
    [0x04] = "Reset Target",
    [0x40] = "Set KitProg Protocol",
    [0x41] = "Synchronize Transfer",
    [0x42] = "Acquire SWD Target",
    [0x43] = "Reset SWD Bus"
}

-- Supported KitProg protocols
local protocols = {
    [0x00] = "JTAG",
    [0x01] = "SWD"
}

-- Supported device types
local device_types = {
    [0x00] = "PSoC 4",
    [0x03] = "PSoC 5 (?)"
}

-- Supported acquire modes
local acquire_modes = {
    [0x00] = "Reset",
    [0x01] = "Power Cycle"
}

-- Return codes
local statuses = {
    [0x00] = "NOK, NACK",
    [0x01] = "OK, ACK"
}

-- Create the fields exhibited by the protocol.
p_kitprog.fields.command_type = ProtoField.uint8("kitprog.command_type", "Command type", base.HEX, command_types)
p_kitprog.fields.command = ProtoField.uint8("kitprog.command", "Command ID", base.HEX, commands)
p_kitprog.fields.mode = ProtoField.uint8("kitprog.mode", "Programming operation type", base.HEX, modes)

p_kitprog.fields.protocol = ProtoField.uint8("kitprog.protocol", "KitProg protocol type", base.HEX, protocols)

p_kitprog.fields.device_type = ProtoField.uint8("kitprog.device_type", "Target device type", base.HEX, device_types, 0x0f)
p_kitprog.fields.acquire_mode = ProtoField.uint8("kitprog.acquire_mode", "Target acquire mode", base.HEX, acquire_modes, 0xf0)
p_kitprog.fields.attempts = ProtoField.uint8("kitprog.attempts", "Maximum target acquisition attempts", base.DEC)

p_kitprog.fields.status = ProtoField.uint8("kitprog.status", "KitProg status", base.HEX, statuses)

p_kitprog.fields.swd_out = ProtoField.bytes("kitprog.swd_out", "SWD data out")
p_kitprog.fields.swd_in = ProtoField.bytes("kitprog.swd_in", "SWD data in")

p_kitprog.fields.unknown = ProtoField.bytes("kitprog.unknown", "Unidentified message data")

-- Referenced USB URB dissector fields.
local f_urb_type = Field.new("usb.urb_type")
local f_transfer_type = Field.new("usb.transfer_type")
local f_endpoint = Field.new("usb.endpoint_number.endpoint")
local f_len = Field.new("frame.len")

-- Insert warning for undecoded leftover data.
local function warn_undecoded(tree, range)
    local item = tree:add(p_kitprog.fields.unknown, range)
    item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
end

-- Dissect KitProg control command messages.
local function dissect_control_command(buffer, pinfo, subtree)
    local command_type = buffer(0,1)
    local command = buffer(1,1)
    local mode = buffer(2,1)

    subtree:add(p_kitprog.fields.command_type, command_type)
    subtree:add(p_kitprog.fields.command, command)
    subtree:add(p_kitprog.fields.mode, mode)

    -- Determine what protocol the KitProg was set to
    if (mode:uint() == 0x40) then
        subtree:add(p_kitprog.fields.protocol, buffer(3,1))
    elseif (mode:uint() == 0x42) then
        subtree:add(p_kitprog.fields.device_type, buffer(3,1))
        subtree:add(p_kitprog.fields.acquire_mode, buffer(3,1))
        subtree:add(p_kitprog.fields.attempts, buffer(4,1))
    end
end

-- Dissect KitProg control response messages.
local function dissect_control_response(buffer, pinfo, subtree)
    subtree:add(p_kitprog.fields.status, buffer(0,1))
end

-- Main KitProg dissector function.
function p_kitprog.dissector(buffer, pinfo, tree)
    local transfer_type = tonumber(tostring(f_transfer_type()))
    local endpoint = tonumber(tostring(f_endpoint()))
    local urb_type = tonumber(tostring(f_urb_type()))

    if ( (transfer_type == 2) and (endpoint == 0) ) then
        -- Control transfers to endpoint 0 only.
        local f_len = tonumber(tostring(f_len()))-64
        local subtree = tree:add(p_kitprog, buffer(), "KitProg Control")

        -- Command-carrying packets only.
        if ( (urb_type == 0x53) ) then
            dissect_control_command(buffer, pinfo, subtree)
        elseif (urb_type == 0x43) then
            dissect_control_response(buffer, pinfo, subtree)
        end
    elseif (transfer_type == 3) then
        -- Bulk transfers
        local subtree = tree:add(p_kitprog, buffer(), "KitProg Bulk")

        -- We only care about the IN and OUT endpoints
        if ( (urb_type == 0x53) and (endpoint == 2) ) then
            -- Data out
            subtree:add(p_kitprog.fields.swd_out, buffer())
        elseif ( (urb_type == 0x43) and (endpoint == 1) ) then
            -- Data in
            subtree:add(p_kitprog.fields.swd_in, buffer())
        end
    end
    return 0
end

function p_kitprog.init()
    local usb_product_dissectors = DissectorTable.get("usb.product")

    -- Dissection by vendor+product ID requires that Wireshark can get the
    -- the device descriptor.  Making a USB device available inside VirtualBox
    -- will make it inaccessible from Linux, so Wireshark cannot fetch the
    -- descriptor by itself.  However, it is sufficient if the VirtualBox
    -- guest requests the descriptor once while Wireshark is capturing.
    usb_product_dissectors:add(0x04b4f139, p_kitprog)

    -- Addendum: Protocol registration based on product ID does not always
    -- work as desired.  Register the protocol on the interface class instead.
    -- The downside is that it would be a bad idea to put this into the global
    -- configuration, so one has to make do with -X lua_script: for now.
    -- local usb_control_dissectors = DissectorTable.get("usb.control")

    -- For some reason the "unknown" class ID is sometimes 0xFF and sometimes
    -- 0xFFFF.  Register both to make it work all the time.
    -- usb_control_dissectors:add(0xFF, p_kitprog)
    -- usb_control_dissectors:add(0xFFFF, p_kitprog)
end
