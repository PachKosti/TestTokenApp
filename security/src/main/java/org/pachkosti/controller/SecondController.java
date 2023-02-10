package org.pachkosti.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/secured")
public class SecondController {

    @GetMapping("/one")
    public String test(){
        return "ide";
    }
}
