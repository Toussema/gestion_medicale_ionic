import { Component, Input } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { IonicModule, PopoverController } from '@ionic/angular';
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

  constructor(private router: Router, private authService: AuthService, private popoverController: PopoverController) {}

  // Méthode publique pour ouvrir le menu comme popover
  async openProfileMenu(event: Event, isLoggedIn: boolean, user: { name: string; role: string }) {
    const popover = await this.popoverController.create({
      component: ProfileMenuComponent,
      event: event,
      componentProps: {
        isLoggedIn: isLoggedIn,
        user: user
      },
      translucent: true,
      backdropDismiss: true,
      dismissOnSelect: true
    });

    // Gérer la fermeture pour éviter l’erreur aria-hidden
    popover.onDidDismiss().then(() => {
      const activeElement = document.activeElement as HTMLElement;
      if (activeElement) {
        activeElement.blur();
      }
    });

    await popover.present();
  }

  async logout() {
    this.authService.logout();
    await this.router.navigate(['/home']);
    await this.popoverController.dismiss(); // Fermer le popover
  }

  async navigateTo(route: string) {
    await this.router.navigate([route]);
    await this.popoverController.dismiss(); // Fermer le popover
  }

  // Nouvelle méthode pour naviguer vers l’espace personnel
  async goToPersonalSpace() {
    if (this.user.role === 'patient') {
      await this.router.navigate(['/espace-patient']);
    } else if (this.user.role === 'medecin') {
      await this.router.navigate(['/espace-medecin']);
    }
    await this.popoverController.dismiss(); // Fermer le popover
  }
  
}
