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

package nl.axelkoolhaas.frida_java.unit;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import nl.axelkoolhaas.frida_java.frida.RpcManager;

public class RpcManagerTest {

  @Test
  void extractRpcResultParsesTopLevelArray() {
    String message = "[\"frida:rpc\",\"rpc-1\",\"ok\",\"world\"]";

    RpcManager.RpcResult result = RpcManager.extractRpcResult(message);

    assertNotNull(result);
    assertEquals("rpc-1", result.getRpcId());
    assertEquals("world", result.getResult());
  }

  @Test
  void extractRpcResultParsesPayloadEnvelope() {
    String message = "{\"type\":\"send\",\"payload\":[\"frida:rpc\",\"rpc-2\",\"ok\",8]}";

    RpcManager.RpcResult result = RpcManager.extractRpcResult(message);

    assertNotNull(result);
    assertEquals("rpc-2", result.getRpcId());
    assertEquals(8, result.getResult());
  }

  @Test
  void extractRpcResultReturnsNullForNonRpcMessage() {
    String message = "{\"type\":\"send\",\"payload\":{\"event\":\"hello\"}}";

    RpcManager.RpcResult result = RpcManager.extractRpcResult(message);

    assertNull(result);
  }
}
