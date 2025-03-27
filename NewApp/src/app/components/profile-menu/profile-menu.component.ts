import { Component, Input } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { IonicModule } from '@ionic/angular';
import { CommonModule } from '@angular/common';



@Component({
  selector: 'app-profile-menu',
  imports: [IonicModule, CommonModule],  // Ajoute cette ligne

  templateUrl: './profile-menu.component.html',
  styleUrls: ['./profile-menu.component.css']
})


export class ProfileMenuComponent {

  @Input() isLoggedIn: boolean = false;
  @Input() user: { name: string; role: string } = { name: '', role: '' }; // Initialiser avec une valeur par défaut

  constructor(private router: Router, private authService: AuthService) {}

  logout() {
    this.authService.logout();
    this.router.navigate(['/home']);
  }

  navigateTo(route: string) {
    this.router.navigate([route]);
  }

  
}
