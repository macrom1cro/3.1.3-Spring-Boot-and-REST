package crud.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;


@Controller
@RequestMapping(value = "/")
public class AdminController {

    @GetMapping("/admin")
    public String listUsers() {
        return "/admin/users";
    }

    @GetMapping("/login")
    public String loginPage(Principal principal) {
        if (principal != null) {
            return "redirect:/admin";
        }
        return "/login";
    }

    @GetMapping("/user")
    public String showUserPage() {
        return "/user/user";
    }

    @GetMapping("/index")
    public String index() {
        return "/index";
    }
}
