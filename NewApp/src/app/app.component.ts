import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './services/auth.service'; // Service d'authentification
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
      componentProps: {
        isLoggedIn: this.isLoggedIn,
        user: this.user,
      },
    });
    await popover.present();
  }
}
