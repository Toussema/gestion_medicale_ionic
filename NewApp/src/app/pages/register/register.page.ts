import { Component } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-register',
  templateUrl: './register.page.html',
  styleUrls: ['./register.page.scss'],
  standalone: false,
})
export class RegisterPage {

  name: string ='';
  email: string = '';
  password: string = '';

  constructor(private authService: AuthService, private router: Router) {}

  register() {
    if (!this.name || !this.email || !this.password) {
      alert('Veuillez remplir tous les champs.');
      return;
    }

    const user = {
      name: this.name,
      email: this.email,
      password: this.password,
      role: 'patient' // Toujours un patient
    };

    this.authService.register(user).subscribe(
      (res) => {
        alert(res.message || 'Inscription réussie !');
        this.router.navigate(['/login']);
      },
      (err) => {
        alert(err.error?.message || 'Erreur lors de l’inscription.');
      }
    );

    
  }
  goToLogin() {
    this.router.navigate(['/login']);
  }

  goToHome() {
    this.router.navigate(['/home']);
    }
}


