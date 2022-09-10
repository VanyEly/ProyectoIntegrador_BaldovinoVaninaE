/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.portfolio.bve.Security.Entity;

import java.util.Collection;
import org.springframework.security.core.userdetails.UserDetails;

/**
 *
 * @author Ely Yiyi
 */
public class UsuarioPrincipal  implements UserDetails{
    private String nombre;
    private String nombreUsuario;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    
    //Constructor
  public UsuarioPrincipal(String nombre, String nombreUsuario, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        this.nombre = nombre;
        this.nombreUsuario = nombreUsuario;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }
    
  public static UsuarioPrincipal build(Usuario usuario) {
      List<GrantedAuthority> authorities = usuario.getRoles().stream().map(rol -> new Simple)
  }
}
