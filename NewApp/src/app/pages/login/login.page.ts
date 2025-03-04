import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.page.html',
  styleUrls: ['./login.page.scss'],
  standalone: false,
})
export class LoginPage {

  email: string = '';
  password: string = '';
  isLoading: boolean = false; // Ajout d'un indicateur de chargement

  constructor(private authService: AuthService, private router: Router) {}

  login() {
    if (!this.email || !this.password) {
      alert('Veuillez remplir tous les champs.');
      return;
    }

    this.isLoading = true; // Début du chargement

    this.authService.login(this.email, this.password).subscribe(
      (response) => {
        console.log('Réponse backend:', response); // 🔍 Vérification
        this.isLoading = false; // Fin du chargement
        

        if (response.token && response.user) {
          this.authService.saveToken(response.token);
          this.authService.saveUser(response.user); // Sauvegarde de l'utilisateur avec son rôle

          alert(response.message || 'Connexion réussie !');

          // Redirection selon le rôle
          if (response.user.role === 'patient') {
            this.router.navigate(['/espace-patient']);
          } else if (response.user.role === 'medecin') {
            this.router.navigate(['/espace-medecin']);
          } else {
            this.router.navigate(['/home']); // Par défaut
          }
        } else {
          alert('Erreur de connexion. Veuillez réessayer.');
        }
      },
      (err) => {
        this.isLoading = false; // Fin du chargement en cas d'erreur
        console.error('Erreur de connexion:', err);
        alert(err.error?.message || 'Erreur lors de la connexion.');
      }
    );
  }

  goToRegister() {
    this.router.navigate(['/register']);
  }

  goToHome() {
    this.router.navigate(['/home']);
    }
}
