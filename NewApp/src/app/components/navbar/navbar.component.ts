import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';


@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css'],
})
export class NavbarComponent implements OnInit {
  isLoggedIn = false;
  userName: string | null = null;
  userRole: string | null = null;

  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit() {
    this.checkUserStatus();
  }

  checkUserStatus() {
    const user = this.authService.getUser();
    this.isLoggedIn = this.authService.isLoggedIn();
    
    if (user) {
      this.userName = user.nom;  // Suppose que l'utilisateur a un champ "nom"
      this.userRole = user.role; // Peut être 'patient' ou 'medecin'
    }
  }

  logout() {
    this.authService.logout();
    this.router.navigate(['/home']); // Redirection après déconnexion
  }

  goToLogin() {
    this.router.navigate(['/login']);
  }

  goToRegister() {
    this.router.navigate(['/register']);
  }
}
