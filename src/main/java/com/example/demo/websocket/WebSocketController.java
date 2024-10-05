package com.example.demo.websocket;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

@Controller
public class WebSocketController {

    @MessageMapping("/sendMessage") // 클라이언트에서 보낸 메시지 처리
    @SendTo("/topic/messages") // 모든 구독자에게 메시지 전송
    public String sendMessage(String message) {
        return message; // 클라이언트에게 메시지 전송
    }
}

