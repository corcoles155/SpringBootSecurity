package org.sanchez.corccoles.ana.pruebasconcepto.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequestMapping("/")
public class LoginController {

    @RequestMapping("login")
    public ModelAndView gotoHome(){
        return new ModelAndView("login");
    }
}
