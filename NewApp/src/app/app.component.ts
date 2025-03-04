import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './services/auth.service'; // Service d'authentification


@Component({
  selector: 'app-root',
  templateUrl: 'app.component.html',
  styleUrls: ['app.component.scss'],
  standalone: false,
})
export class AppComponent {
  isProfileMenuOpen = false; // Contrôle l'état du menu profil
  isLoggedIn = false; // Indique si l'utilisateur est connecté
  user: { name: string; role: string } | null = null; // Informations de l'utilisateur


  constructor(private router: Router, private authService: AuthService) {
    // Vérifier l'état de connexion et récupérer les informations de l'utilisateur
    this.authService.isLoggedIn$.subscribe((loggedIn) => {
      this.isLoggedIn = loggedIn;
      if (loggedIn) {
        this.user = this.authService.getUser(); // Récupérer les infos de l'utilisateur
      } else {
        this.user = null;
      }
    });
  }

  /**
   * Ouvre le menu profil.
   */
  openProfileMenu(event: Event) {
    event.stopPropagation(); // Empêche la propagation de l'événement
    this.isProfileMenuOpen = true;
  }

  /**
   * Ferme le menu profil.
   */
  closeProfileMenu() {
    this.isProfileMenuOpen = false;
  }

  /**
   * Redirige vers la page d'inscription.
   
  goToRegister() {
    this.router.navigate(['/register']);
    this.closeProfileMenu();
  } */

  /**
   * Redirige vers la page de connexion.
   
  goToLogin() {
    this.router.navigate(['/login']);
    this.closeProfileMenu();
  } */

    /**
   * Déconnecte l'utilisateur.
   */
    logout() {
      this.authService.logout(); // Appeler la méthode de déconnexion
      this.closeProfileMenu();
      this.router.navigate(['/home']); // Rediriger vers la page d'accueil
    }

      /* Navigue vers une page spécifique. */
  navigateTo(route: string) {
    this.router.navigate([route]);
    this.closeProfileMenu();

  }
}
