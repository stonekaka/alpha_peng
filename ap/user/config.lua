
local json = require "luci.json"
local uci    = require "uci"
local fs = require "nixio.fs"

local _uci = uci.cursor()

function get_json_from_file(filepath)
    local data = {}
    if fs.access(filepath) then
        local fd = io.open(filepath, 'r')
        if fd then
            data = json.decode(fd:read("*all"))
        end
        fd:close()
        return data
    else
        return nil
    end
end

function config(_filename)
	local cf = {}
	
	cf = get_json_from_file(_filename)	
	if not cf then
		print('read json file error.')
		return nil
	end

	_uci:set("wireless", device_cnf['.name'], opt, tostring(val))
	_uci:save("ezwrt")
	_uci:commit("ezwrt")
	
end


config('/tmp/abc')

