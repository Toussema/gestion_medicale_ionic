import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './services/auth.service';
import { PopoverController } from '@ionic/angular';
import { ProfileMenuComponent } from './components/profile-menu/profile-menu.component';

@Component({
  selector: 'app-root',
  templateUrl: 'app.component.html',
  styleUrls: ['app.component.scss'],
  standalone: false,
})
export class AppComponent {
  isLoggedIn = false;
  user: { name: string; role: string } | null = null;

  constructor(
    private authService: AuthService,
    private popoverController: PopoverController
  ) {
    this.authService.isLoggedIn$.subscribe((loggedIn) => {
      this.isLoggedIn = loggedIn;
      if (loggedIn) {
        this.user = this.authService.getUser();
      } else {
        this.user = null;
      }
    });
  }

  async openProfileMenu(event: Event) {
    const popover = await this.popoverController.create({
      component: ProfileMenuComponent,
      event: event,
      translucent: false,
      cssClass: 'custom-popover',
      backdropDismiss: true,
      dismissOnSelect: true,
      componentProps: {
        isLoggedIn: this.isLoggedIn,
        user: this.user,
      },
    });

    await popover.present();

    popover.onDidDismiss().then(() => {
      // Retirer le focus des éléments à l'intérieur du popover
      const activeElement = document.activeElement as HTMLElement;
      if (activeElement) {
        activeElement.blur();
      }

      // Forcer l'attribut inert sur le popover
      const popoverElement = document.querySelector(`#${popover.id}`);
      if (popoverElement) {
        popoverElement.setAttribute('inert', '');
        popoverElement.setAttribute('aria-hidden', 'true');
      }

      // Déplacer le focus vers le bouton de profil
      const profileButton = document.querySelector('ion-button[title="Profile"]') as HTMLElement;
      if (profileButton) {
        profileButton.focus();
      }
    });
  }
}