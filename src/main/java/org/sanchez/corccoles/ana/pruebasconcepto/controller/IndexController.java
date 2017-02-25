package org.sanchez.corccoles.ana.pruebasconcepto.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class IndexController {

    @RequestMapping("home")
    public String gotoHome(){
        return "home";
    }

    @RequestMapping("admin")
    public String gotoAdmin(){
        return "admin";
    }

    @RequestMapping("superadmin")
    @PreAuthorize(value = "hasRole('ROLE_SUPERADMIN')")
    public String gotoSuperAdmin(){
        return "superadmin";
    }
}
