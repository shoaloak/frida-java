/*
 * Copyright (C) 2026 Axel Koolhaas
 *
 * This file is part of frida-java.
 *
 * frida-java is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * frida-java is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with frida-java.  If not, see <https://www.gnu.org/licenses/>.
 */

package nl.axelkoolhaas.frida_java.frida;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages RPC call infrastructure for Frida scripts
 */
public class RpcManager {
    private static final Logger log = LoggerFactory.getLogger(RpcManager.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Map<String, CompletableFuture<Object>> RPC_CALLS = new ConcurrentHashMap<>();

    /**
     * Create a new RPC call structure
     * @param functionName The function name to call
     * @param args Arguments to pass to the function
     * @return RPC call data array
     */
    public static Object[] createRpcCall(String functionName, Object... args) {
        String rpcId = UUID.randomUUID().toString().substring(0, 16);
        log.debug("Creating RPC call: function={}, rpcId={}", functionName, rpcId);

        Object[] rpcData = new Object[] {
            "frida:rpc",
            rpcId,
            "call",
            functionName
        };

        // Create the full RPC array
        Object[] rpc = new Object[rpcData.length + 1];
        System.arraycopy(rpcData, 0, rpc, 0, rpcData.length);

        if (args != null && args.length > 0) {
            rpc[rpc.length - 1] = Arrays.asList(args);
        } else {
            rpc[rpc.length - 1] = Collections.emptyList();
        }

        return rpc;
    }

    /**
     * Register an RPC call and return its future
     * @param rpcId The RPC call ID
     * @return CompletableFuture for the result
     */
    public static CompletableFuture<Object> registerRpcCall(String rpcId) {
        CompletableFuture<Object> future = new CompletableFuture<>();
        RPC_CALLS.put(rpcId, future);
        log.trace("Registered RPC call: rpcId={}", rpcId);
        return future;
    }

    /**
     * Extract RPC ID and result from a message
     * @param message JSON message from script
     * @return RPC ID and result, or null if not an RPC response
     */
    public static RpcResult extractRpcResult(String message) {
        try {
            JsonNode node = OBJECT_MAPPER.readTree(message);

            if (node.isArray() && node.size() >= 4 && "frida:rpc".equals(node.get(0).stringValue())) {
                String rpcId = node.get(1).stringValue();
                Object result = node.get(3);
                log.trace("Extracted RPC result: rpcId={}", rpcId);
                return new RpcResult(rpcId, result);
            }
        } catch (Exception e) {
            // Not an RPC message
            log.trace("Message is not a valid RPC response: {}", e.getMessage());
        }

        return null;
    }

    /**
     * Complete an RPC call with its result
     * @param rpcId The RPC call ID
     * @param result The result to return
     */
    public static void completeRpcCall(String rpcId, Object result) {
        CompletableFuture<Object> future = RPC_CALLS.remove(rpcId);
        if (future != null) {
            future.complete(result);
        }
    }

    /**
     * Convert Object array to JSON string
     * @param rpcCall The RPC call array
     * @return JSON string
     */
    public static String toJsonString(Object[] rpcCall) {
        try {
            return OBJECT_MAPPER.writeValueAsString(rpcCall);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to serialize RPC call", e);
        }
    }

    /**
     * Parse a JsonNode into a Java Object
     */
    private static Object parseJsonValue(JsonNode node) {
        if (node.isNull()) {
            return null;
        } else if (node.isBoolean()) {
            return node.asBoolean();
        } else if (node.isInt()) {
            return node.asInt();
        } else if (node.isLong()) {
            return node.asLong();
        } else if (node.isDouble()) {
            return node.asDouble();
        } else if (node.isString()) {
            return node.asString();
        } else if (node.isArray()) {
            List<Object> list = new ArrayList<>();
            for (JsonNode element : node) {
                list.add(parseJsonValue(element));
            }
            return list;
        } else if (node.isObject()) {
            Map<String, Object> map = new HashMap<>();
            for (String fieldName : node.propertyNames()) {
                map.put(fieldName, parseJsonValue(node.get(fieldName)));
            }
            return map;
        }
        return node.toString();
    }

    /**
     * Data class for RPC results
     */
    public static class RpcResult {
        private final String rpcId;
        private final Object result;

        public RpcResult(String rpcId, Object result) {
            this.rpcId = rpcId;
            this.result = result;
        }

        public String getRpcId() {
            return rpcId;
        }

        public Object getResult() {
            return result;
        }
    }
}
