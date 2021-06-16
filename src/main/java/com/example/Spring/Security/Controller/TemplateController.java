package com.example.Spring.Security.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping(path = "login")
    public String getLoginForm() {
        return "login";
    }
    @GetMapping(path = "home")
    public String getHomePage() {
        return "home";
    }
}
