import { Component, Input } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { IonicModule, PopoverController } from '@ionic/angular';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-profile-menu',
  templateUrl: './profile-menu.component.html',
  styleUrls: ['./profile-menu.component.css'],
  standalone: true, // Ajout pour cohérence avec Ionic 7 standalone components
  imports: [IonicModule, CommonModule],
})
export class ProfileMenuComponent {
  @Input() isLoggedIn: boolean = false;
  @Input() user: { name: string; role: string } = { name: '', role: '' };

  constructor(
    private router: Router,
    private authService: AuthService,
    private popoverController: PopoverController
  ) {}

  async logout() {
    // Retirer le focus avant de fermer
    const activeElement = document.activeElement as HTMLElement;
    if (activeElement) {
      activeElement.blur();
    }
    await this.authService.logout();
    await this.router.navigate(['/home']);
    await this.popoverController.dismiss();
  }

  async navigateTo(route: string) {
    // Retirer le focus avant de naviguer
    const activeElement = document.activeElement as HTMLElement;
    if (activeElement) {
      activeElement.blur();
    }
    await this.router.navigate([route]);
    await this.popoverController.dismiss();
  }

  async goToPersonalSpace() {
    // Retirer le focus avant de naviguer
    const activeElement = document.activeElement as HTMLElement;
    if (activeElement) {
      activeElement.blur();
    }
    if (this.user.role === 'patient') {
      await this.router.navigate(['/espace-patient']);
    } else if (this.user.role === 'medecin') {
      await this.router.navigate(['/espace-medecin']);
    }
    await this.popoverController.dismiss();
  }
}