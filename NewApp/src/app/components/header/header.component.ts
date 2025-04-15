import { Component, EventEmitter, Output, OnInit, ElementRef } from '@angular/core';
import { IonicModule, PopoverController } from '@ionic/angular';
import { NotificationsComponent } from '../notifications/notifications.component';
import { CommonModule } from '@angular/common';
import { DocumentsService } from '../../services/documents.service';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css'],
  standalone: true,
  imports: [IonicModule, CommonModule]
})
export class HeaderComponent implements OnInit {
  @Output() profileMenuClicked = new EventEmitter<Event>();
  unreadCount: number = 0;
  isLoggedIn = false;
  user: { name: string; role: string } | null = null;

  constructor(
    private popoverController: PopoverController,
    private documentsService: DocumentsService,
    private authService: AuthService,
    private elementRef: ElementRef
  ) {}

  ngOnInit() {
    this.loadUnreadCount();
    this.authService.isLoggedIn$.subscribe((loggedIn) => {
      this.isLoggedIn = loggedIn;
      if (loggedIn) {
        this.user = this.authService.getUser();
      } else {
        this.user = null;
      }
    });
  }

  loadUnreadCount() {
    this.documentsService.getUnreadNotificationsCount().subscribe({
      next: (count) => {
        this.unreadCount = count;
      },
      error: (err) => console.error('Erreur lors du chargement du compte des notifications non lues', err)
    });
  }

  onProfileButtonClick(event: Event) {
    event.stopPropagation();
    this.profileMenuClicked.emit(event);
  }

  async onNotificationsClick(event: Event) {
    event.stopPropagation();
    const popover = await this.popoverController.create({
      component: NotificationsComponent,
      event: event,
      translucent: false,
      cssClass: 'custom-popover',
      backdropDismiss: true,
      dismissOnSelect: true,
    });

    await popover.present();

    popover.onDidDismiss().then(() => {
      this.loadUnreadCount();

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

      // Déplacer le focus vers le bouton de notifications
      const notificationsButton = this.elementRef.nativeElement.querySelector('ion-button[title="Notifications"]');
      if (notificationsButton) {
        notificationsButton.focus();
      }
    });
  }
}